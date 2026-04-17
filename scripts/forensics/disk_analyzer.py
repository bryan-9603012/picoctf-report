#!/usr/bin/env python3
import os
import re
import json
import csv
import math
import hashlib
import base64
import subprocess
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from enum import IntEnum

VERSION = "4.0-rc1"
DEFAULT_FULL_EXPORT_TIMELINE_LIMIT = 1000

MAGIC_BYTES = {
    b'\x7fELF': 'ELF executable',
    b'\x89PNG': 'PNG image',
    b'\xff\xd8\xff': 'JPEG image',
    b'GIF8': 'GIF image',
    b'BM': 'BMP image',
    b'PK\x03\x04': 'ZIP archive',
    b'\x1f\x8b': 'GZIP compressed',
    b'Rar!': 'RAR archive',
    b'\x00\x00\x01\x00': 'ICO image',
    b'%PDF': 'PDF document',
    b'\xca\xfe\xba\xbe': 'Java class/Mach-O',
    b'\x4f\x67\x67\x53': 'Ogg audio/video',
    b'RIFF': 'RIFF media (AVI/WAV)',
    b'\xfd7zXZ': 'XZ compressed',
    b'BZh': 'BZIP2 compressed',
    b'8BPS': 'PSD image',
    b'II*\x00': 'TIFF image (little endian)',
    b'MM\x00*': 'TIFF image (big endian)',
    b'dex\n': 'Android DEX',
    b'\x1f\x9d': 'LZW compressed',
}

EXTENSION_MAGIC_MAPPING = {
    '.png': ['PNG image'],
    '.jpg': ['JPEG image'],
    '.jpeg': ['JPEG image'],
    '.gif': ['GIF image'],
    '.bmp': ['BMP image'],
    '.ico': ['ICO image'],
    '.pdf': ['PDF document'],
    '.zip': ['ZIP archive'],
    '.gz': ['GZIP compressed'],
    '.bz2': ['BZIP2 compressed'],
    '.xz': ['XZ compressed'],
    '.rar': ['RAR archive'],
    '.elf': ['ELF executable'],
    '.ko': ['ELF executable'],
    '.dex': ['Android DEX'],
    '.ogg': ['Ogg audio/video'],
    '.wav': ['RIFF media (AVI/WAV)'],
    '.avi': ['RIFF media (AVI/WAV)'],
    '.psd': ['PSD image'],
    '.tiff': ['TIFF image (little endian)', 'TIFF image (big endian)'],
    '.tif': ['TIFF image (little endian)', 'TIFF image (big endian)'],
}

EXTENSION_MISMATCH_SEVERITY = {
    ('.png', 'ELF executable'): 3,
    ('.jpg', 'ELF executable'): 3,
    ('.png', 'ZIP archive'): 2,
    ('.zip', 'ELF executable'): 3,
    ('.txt', 'ELF executable'): 2,
    ('.txt', 'ZIP archive'): 2,
    ('.pdf', 'HTML'): 2,
    ('.pdf', 'ELF executable'): 3,
    ('.jpg', 'ZIP archive'): 2,
    ('.png', 'PDF document'): 2,
    ('.pdf', 'ZIP archive'): 2,
    ('.txt', 'PDF document'): 2,
    ('.wav', 'ELF executable'): 3,
}

CTF_KEYWORDS = [
    'picoCTF', 'flag', 'ctf', 'password', 'passwd', 'secret', 'key',
    'token', 'credential', 'auth', 'hash', 'admin', 'root', 'hidden',
    'private', 'confidential', 'classified', 'topsecret', 'api_key',
    'aws_access', 'aws_secret', 'private_key', 'ssh-rsa', 'ssh-dss'
]

HIGH_PRIORITY_PATTERNS = [
    (r'picoCTF\{[^}]+\}', 3, 'CTF flag pattern'),
    (r'flag\{[^}]+\}', 3, 'Flag pattern'),
    (r'ssh[_-]?[rd]sa', 3, 'SSH key'),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 3, 'Private key'),
    (r'-----BEGIN CERTIFICATE-----', 1, 'SSL certificate'),
    (r'AKIA[0-9A-Z]{16}', 3, 'AWS access key'),
]

WHITELIST_PATHS = [
    '/etc/ssl/', '/etc/ssl/certs/', '/usr/share/ca-certificates/',
    '/etc/apk/', '/lib/modules/', '/etc/ssl1.1/', '/etc/ca-certificates/',
    '/usr/share/ca-certificates/', '/etc/mkinitfs/', '/etc/modprobe.d/',
    '/etc/modules-load.d/', '/etc/sysctl.d/', '/etc/udhcpc/',
    '/etc/network/', '/etc/logrotate.d/', '/etc/periodic/',
    '/etc/runlevels/', '/etc/init.d/', '/etc/conf.d/', '/etc/lbu/',
    '/etc/acpi/', '/etc/crontabs/', '/etc/zoneinfo/', '/etc/terminfo/',
    '/etc/profile.d/', '/etc/secfixes.d/', '/etc/vim/', '/etc/doas.d/',
]

SUSPICIOUS_EXTENSIONS = [
    '.bak', '.tmp', '.swp', '.old', '.backup', '.pass', '.pwd',
    '.key', '.pem', '.crt', '.der', '.gpg', '.pgp', '.ovpn',
    '.history', '.bash_history', '.viminfo', '.ash_history'
]

SUSPICIOUS_WHITELIST = [
    '/usr/share/apk/keys/',
    '/usr/share/vim/',
    '/usr/bin/ssh',
    '/usr/sbin/sshd',
    '/usr/bin/openssl',
    '/usr/share/ca-certificates/',
    '/lib/modules/',
    '/etc/ssl/certs/',
    '/usr/share/ca-certificates/',
]

SYSTEM_WHITELIST = [
    '/etc/resolv.conf',
    '/etc/apk/world',
    '/etc/hostname',
    '/etc/hosts',
    '/etc/passwd',
    '/etc/group',
    '/etc/shadow',
    '/etc/mtab',
    '/etc/fstab',
    '/lib/rc/cache/softlevel',
    '/var/lib/seedrng/seed.credit',
]

HIGH_PRIORITY_PATHS = ['/etc/', '/root/', '/tmp/', '/var/tmp/', '/home/', '/bin/', '/usr/local/bin/']
MEDIUM_PRIORITY_PATHS = ['/var/', '/opt/']

CRITICAL_PATHS = ['/root', '/tmp', '/var/tmp', '/home']

class Severity(IntEnum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

class DiskAnalyzer:
    def __init__(self, path: str, verbose: bool = False):
        self.path = Path(path).resolve()
        self.verbose = verbose
        self.is_image = False
        self.image_type = None
        self.partition_offset = 0
        self.selected_partition = None
        self.partitions: List[Dict] = []
        
        self.files: List[Dict] = []
        self.file_stats = defaultdict(lambda: {'count': 0, 'size': 0})
        self.total_size = 0
        self.file_count = 0
        self.findings: List[Dict] = []
        self.timeline: List[Dict] = []
        
        self.cached_decoded_payloads = None
        self.cached_oldest_suspicious = None
        self.cached_recent_suspicious = None
        self.cached_time_outliers = None
        
        self.inode_content_cache: Dict[int, bytes] = {}
        self.inode_stat_cache: Dict[int, Dict] = {}
        self.inode_istat_cache: Dict[int, Dict] = {}
        
        self._cache_access_order: List[int] = []
        self._cache_max_size = 500
        self._content_cache_max_bytes = 64 * 1024
        
    def log(self, msg: str):
        if self.verbose:
            print(f"  [+] {msg}")
    
    def create_finding(self, file_info: Dict, severity: int, reason: str, 
                       category: str, **kwargs) -> Dict:
        finding = {
            'path': file_info.get('path', ''),
            'inode': file_info.get('inode'),
            'size': file_info.get('size', 0),
            'mtime': file_info.get('mtime', 0),
            'atime': file_info.get('atime', 0),
            'ctime': file_info.get('ctime', 0),
            'crtime': file_info.get('crtime', 0),
            'is_dir': file_info.get('is_dir', False),
            'source': file_info.get('source', 'unknown'),
            'severity': severity,
            'reason': reason,
            'category': category,
            'reasons': kwargs.get('reasons', [reason]),
            'rule_id': kwargs.get('rule_id', 'GENERIC-001'),
            'confidence': kwargs.get('confidence', 'medium'),
            'evidence_type': kwargs.get('evidence_type', category),
            'method': kwargs.get('method', 'unknown'),
        }
        finding.update(kwargs)
        return finding
    
    def format_size(self, size: float) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    
    def format_time(self, ts: float) -> str:
        if ts <= 0:
            return 'N/A'
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    
    def sanitize_filename(self, name: str, max_len: int = 100) -> str:
        safe = re.sub(r'[^A-Za-z0-9._-]', '_', name)
        return safe[:max_len].strip('_')
    
    def get_severity_name(self, severity: int) -> str:
        try:
            return Severity(severity).name
        except ValueError:
            return 'INFO'
    
    def build_session_info(self, options: Optional[Dict] = None) -> Dict:
        options = options or {}
        return {
            'deep_analysis_enabled': options.get('deep', False),
            'content_analysis_enabled': options.get('content', False),
            'time_correlations_enabled': options.get('time_correlations', False),
            'decode_base64_enabled': options.get('decode_base64', False),
            'max_file_size': options.get('max_size', 5*1024*1024),
            'timeline_limit_used': options.get('timeline_limit'),
        }
    
    def build_export_info(self) -> Dict:
        return {
            'version': VERSION,
            'timeline_total': len(self.timeline),
            'full_export_timeline_limit': DEFAULT_FULL_EXPORT_TIMELINE_LIMIT,
            'timeline_json_default': 'unlimited',
            'artifacts_supported': True,
            'artifact_types': ['decoded_payload', 'finding'],
        }
    
    def serialize_payload(self, p: Dict) -> Dict:
        return {
            'artifact_type': 'decoded_payload',
            'path': p.get('path'),
            'inode': p.get('inode'),
            'size': p.get('size'),
            'mtime': p.get('mtime'),
            'atime': p.get('atime'),
            'ctime': p.get('ctime'),
            'confidence': 'high' if p.get('score', 0) > 50 else 'medium',
            'method': 'base64_decode+heuristic',
            'source': p.get('source', 'icat'),
            'decoded': p.get('decoded'),
            'reason': p.get('reason'),
            'score': p.get('score'),
            'quality': p.get('quality'),
        }
    
    def severity_from_str(self, s: str) -> int:
        mapping = {'高': Severity.HIGH, '中': Severity.MEDIUM, '低': Severity.LOW}
        return mapping.get(s, Severity.INFO)
    
    def detect_image_type(self) -> Optional[str]:
        file_cmd = subprocess.run(['file', str(self.path)], capture_output=True, text=True)
        output = file_cmd.stdout.lower()
        
        if 'ext4' in output or 'linux rev 1.0 ext4' in output:
            self.is_image = True
            self.image_type = 'ext4'
            return 'ext4'
        elif 'ext3' in output or 'linux rev 1.0 ext3' in output:
            self.is_image = True
            self.image_type = 'ext3'
            return 'ext3'
        elif 'ext2' in output or 'linux rev 1.0 ext2' in output:
            self.is_image = True
            self.image_type = 'ext2'
            return 'ext2'
        elif 'ext' in output:
            self.is_image = True
            self.image_type = 'ext'
            return 'ext'
        elif 'filesystem' in output:
            self.is_image = True
            return 'unknown_filesystem'
        return None
    
    def detect_partitions(self) -> List[Dict]:
        partitions = []
        
        try:
            mmls_cmd = subprocess.run(['mmls', str(self.path)], capture_output=True, text=True, timeout=30)
            if mmls_cmd.returncode == 0:
                lines = mmls_cmd.stdout.split('\n')
                for line in lines:
                    if re.match(r'^\s*\d+\s+\d+\s+\d+\s+', line):
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 4:
                            try:
                                start_sector = int(parts[1])
                                end_sector = int(parts[2])
                                desc = ' '.join(parts[3:]) if len(parts) > 3 else ''
                                
                                is_linux = any(x in desc.lower() for x in ['linux', 'ext', 'swap', '0x83'])
                                part_type = 'unknown'
                                if 'linux' in desc.lower() or 'ext' in desc.lower():
                                    part_type = 'linux'
                                elif 'swap' in desc.lower():
                                    part_type = 'swap'
                                elif 'ntfs' in desc.lower() or '0x07' in desc.lower():
                                    part_type = 'ntfs'
                                elif 'fat' in desc.lower() or '0x0c' in desc.lower() or '0x0e' in desc.lower():
                                    part_type = 'fat'
                                
                                partitions.append({
                                    'start_sector': start_sector,
                                    'end_sector': end_sector,
                                    'size_sectors': end_sector - start_sector,
                                    'description': desc,
                                    'type': part_type,
                                    'offset_bytes': start_sector * 512
                                })
                            except (ValueError, IndexError):
                                continue
        except FileNotFoundError:
            self.log('mmls not found, skipping partition detection')
        except subprocess.TimeoutExpired:
            self.log('mmls timed out')
        except Exception as e:
            self.log(f'Partition detection failed: {e}')
        
        return partitions
    
    def select_partition(self, partition_index: int = 0):
        partitions = self.detect_partitions()
        
        if not partitions:
            self.log('No partitions found, using offset 0')
            self.partition_offset = 0
            return None
        
        if partition_index >= len(partitions):
            self.log(f'Invalid partition index, using last partition')
            partition_index = len(partitions) - 1
        
        selected = partitions[partition_index]
        self.partition_offset = selected['offset_bytes']
        self.selected_partition = selected
        
        self.log(f"Selected partition {partition_index}: offset={self.partition_offset}, type={selected['type']}")
        return selected
    
    def get_filesystem_info(self) -> Optional[Dict]:
        if not self.is_image:
            return None
        
        offset = self.partition_offset // 512
        
        try:
            fsstat_cmd = subprocess.run(
                ['fsstat', '-o', str(offset), str(self.path)],
                capture_output=True, text=True, timeout=30
            )
            if fsstat_cmd.returncode == 0:
                info = {'output': fsstat_cmd.stdout}
                
                fs_type_match = re.search(r'File System Type:\s*(\S+)', fsstat_cmd.stdout)
                if fs_type_match:
                    info['fs_type'] = fs_type_match.group(1)
                
                offset_match = re.search(r'Offset \(bytes\):\s*(\d+)', fsstat_cmd.stdout)
                if offset_match:
                    info['offset'] = int(offset_match.group(1))
                
                return info
        except FileNotFoundError:
            self.log('fsstat not found')
        except Exception as e:
            self.log(f'fsstat failed: {e}')
        
        return None
    
    def list_files_fls(self, path: str = '/') -> List[Dict]:
        if not self.is_image:
            return []
        
        offset = self.partition_offset // 512
        
        try:
            fls_cmd = subprocess.run(
                ['fls', '-R', '-l', '-o', str(offset), str(self.path), path],
                capture_output=True, text=True, timeout=60
            )
            if fls_cmd.returncode == 0:
                files = []
                for line in fls_cmd.stdout.split('\n'):
                    match = re.match(r'^\d+\s+(\*)?(\d+):\s+(\S+)\s+(.+)$', line)
                    if match:
                        is_dir = match.group(1) == '*'
                        inode = int(match.group(2))
                        file_type = match.group(3)
                        name = match.group(4)
                        
                        files.append({
                            'inode': inode,
                            'is_dir': is_dir,
                            'type': file_type,
                            'name': name,
                            'path': f"{path}/{name}" if path != '/' else f"/{name}"
                        })
                return files
        except FileNotFoundError:
            self.log('fls not found')
        except Exception as e:
            self.log(f'fls failed: {e}')
        
        return []
    
    def get_inode_info_istat(self, inode: int) -> Optional[Dict]:
        if not self.is_image:
            return None
        
        if inode in self.inode_istat_cache:
            return self.inode_istat_cache[inode]
        
        offset = self.partition_offset // 512
        
        try:
            istat_cmd = subprocess.run(
                ['istat', '-o', str(offset), str(self.path), str(inode)],
                capture_output=True, text=True, timeout=30
            )
            if istat_cmd.returncode == 0:
                info = {'inode': inode}
                
                alloc_match = re.search(r'Allocated:\s*(yes|no)', istat_cmd.stdout)
                if alloc_match:
                    info['allocated'] = alloc_match.group(1) == 'yes'
                
                size_match = re.search(r'Size:\s*(\d+)', istat_cmd.stdout)
                if size_match:
                    info['size'] = int(size_match.group(1))
                
                for time_type in ['Modified', 'Accessed', 'Changed', 'Created']:
                    time_match = re.search(rf'{time_type}:\s*(.+)', istat_cmd.stdout)
                    if time_match:
                        try:
                            ts = datetime.strptime(time_match.group(1).strip(), '%Y-%m-%d %H:%M:%S.%f').timestamp()
                            info[time_type.lower()] = ts
                        except:
                            pass
                
                self.inode_istat_cache[inode] = info
                return info
        except FileNotFoundError:
            self.log('istat not found')
        except Exception as e:
            self.log(f'istat failed: {e}')
        
        return None
    
    def read_file_by_inode_icat(self, inode: int, max_size: int = 1024*1024) -> Optional[bytes]:
        """Read file content via icat (raw read, no cache). Used for bypass cache scenarios."""
        if not self.is_image:
            return None
        
        offset = self.partition_offset // 512
        
        try:
            icat_cmd = subprocess.run(
                ['icat', '-o', str(offset), str(self.path), str(inode)],
                capture_output=True, timeout=30
            )
            if icat_cmd.returncode == 0:
                return icat_cmd.stdout[:max_size]
        except FileNotFoundError:
            self.log('icat not found')
        except Exception as e:
            self.log(f'icat failed: {e}')
        
        return None
    
    def _update_content_cache(self, inode: int, data: bytes):
        if len(data) > self._content_cache_max_bytes:
            return
        
        if len(self.inode_content_cache) >= self._cache_max_size:
            if self._cache_access_order:
                oldest_inode = self._cache_access_order.pop(0)
                self.inode_content_cache.pop(oldest_inode, None)
        
        self.inode_content_cache[inode] = data
        self._cache_access_order.append(inode)
    
    def read_file_from_image(self, inode: int, max_size: int = 1024*1024) -> Optional[bytes]:
        if not self.is_image or not self.image_type.startswith('ext'):
            return None
        
        if inode in self.inode_content_cache:
            if inode in self._cache_access_order:
                self._cache_access_order.remove(inode)
            self._cache_access_order.append(inode)
            return self.inode_content_cache[inode][:max_size]
        
        offset = self.partition_offset // 512
        cmd = ['icat', '-o', str(offset), str(self.path), str(inode)]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                self._update_content_cache(inode, result.stdout)
                return result.stdout[:max_size]
        except:
            pass
        
        return None
    
    def get_file_stat(self, inode: int) -> Optional[Dict]:
        if not self.is_image or not self.image_type.startswith('ext'):
            return None
        
        if inode in self.inode_stat_cache:
            return self.inode_stat_cache[inode]
        
        cmd = ['debugfs', '-R', f'stat <{inode}>', str(self.path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout
            
            stat_info: Dict[str, object] = {'inode': int(inode)}
            
            type_match = re.search(r'Type:\s*(\w+)', output)
            mode_match = re.search(r'Mode:\s*(0x[0-9a-f]+|[0-9]+)', output)
            user_match = re.search(r'User:\s*(\d+)', output)
            group_match = re.search(r'Group:\s*(\d+)', output)
            size_match = re.search(r'Size:\s*(\d+)', output)
            links_match = re.search(r'Links:\s*(\d+)', output)
            
            if type_match:
                stat_info['type'] = type_match.group(1)
            if mode_match:
                stat_info['mode'] = mode_match.group(1)
            if user_match:
                stat_info['uid'] = int(user_match.group(1))
            if group_match:
                stat_info['gid'] = int(group_match.group(1))
            if size_match:
                stat_info['size'] = int(size_match.group(1))
            if links_match:
                stat_info['links'] = int(links_match.group(1))
            
            ctime_match = re.search(r'ctime:.*--\s*(.+)$', output, re.MULTILINE)
            mtime_match = re.search(r'mtime:.*--\s*(.+)$', output, re.MULTILINE)
            atime_match = re.search(r'atime:.*--\s*(.+)$', output, re.MULTILINE)
            crtime_match = re.search(r'crtime:.*--\s*(.+)$', output, re.MULTILINE)
            
            for match, key in [(ctime_match, 'ctime'), (mtime_match, 'mtime'), (atime_match, 'atime')]:
                if match:
                    try:
                        stat_info[key] = datetime.strptime(match.group(1).strip(), '%a %b %d %H:%M:%S %Y').timestamp()
                    except:
                        stat_info[key] = 0.0
                else:
                    stat_info[key] = 0.0
            
            if crtime_match:
                try:
                    stat_info['crtime'] = datetime.strptime(crtime_match.group(1).strip(), '%a %b %d %H:%M:%S %Y').timestamp()
                except:
                    stat_info['crtime'] = 0.0
            else:
                stat_info['crtime'] = 0.0
            
            self.inode_stat_cache[inode] = stat_info
            return stat_info
        except:
            return None
    
    def read_file_content(self, path: str) -> Optional[str]:
        if self.is_image and self.image_type and self.image_type.startswith('ext'):
            inode = self._find_inode_by_path(path)
            if inode:
                data = self.read_file_from_image(inode)
                if data:
                    return data.decode('utf-8', errors='replace')
        return None
    
    def _build_path_index(self) -> Dict[str, int]:
        self.path_index: Dict[str, int] = {}
        for f in self.files:
            if f.get('path') and f.get('inode'):
                self.path_index[f['path']] = f['inode']
        return self.path_index
    
    def _find_inode_by_path(self, path: str) -> Optional[int]:
        if hasattr(self, 'path_index') and path in self.path_index:
            return self.path_index[path]
        
        for f in self.files:
            if f.get('path') == path:
                return f.get('inode')
        
        if hasattr(self, 'path_index'):
            for indexed_path, inode in self.path_index.items():
                if indexed_path.endswith(path) or path.endswith(indexed_path):
                    return inode
        
        parts = path.strip('/').split('/')
        if len(parts) < 2:
            return None
        
        parent_path = '/'.join(parts[:-1])
        target_name = parts[-1]
        
        cmd = ['debugfs', '-R', f'ls -l {parent_path}', str(self.path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in result.stdout.strip().split('\n'):
                match = re.match(r'^\s*(\d+)\s+.*\s+(\S+)\s*$', line)
                if match and match.group(2) == target_name:
                    return int(match.group(1))
        except:
            pass
        return None
    
    def find_files_by_time(self, target_time: datetime, window_seconds: int = 120) -> List[Dict]:
        results = []
        target_ts = target_time.timestamp()
        
        for f in self.files:
            if f.get('is_dir'):
                continue
            
            mtime = f.get('mtime', 0)
            if mtime > 0:
                diff = abs(mtime - target_ts)
                if diff <= window_seconds:
                    results.append({
                        **f,
                        'time_diff': diff,
                        'target_time': target_ts
                    })
        
        return sorted(results, key=lambda x: x['time_diff'])
    
    def scan_image_ext4(self):
        self.log("使用 debugfs 掃描 ext4 映像檔")
        self._scan_ext_recursive('/')
        print(f"已發現 {len(self.files)} 個項目，正在獲取 metadata...")
        
        # 只對有興趣的檔案獲取詳細 metadata
        interesting_files = [f for f in self.files if not f.get('is_dir')][:500]
        for i, f in enumerate(interesting_files):
            if f.get('inode'):
                stat_info = self.get_file_stat(f['inode'])
                if stat_info:
                    f.update(stat_info)
            if (i + 1) % 100 == 0:
                print(f"  已處理 {i+1}/{len(interesting_files)} 個檔案...")
        
        print("Metadata 擷取完成")
    
    def scan_with_fls(self):
        self.log("使用 Sleuth Kit (fls) 掃描映像檔")
        
        offset = self.partition_offset // 512
        
        try:
            fls_cmd = subprocess.run(
                ['fls', '-r', '-p', '-l', '-o', str(offset), str(self.path)],
                capture_output=True, text=True, timeout=120
            )
            
            if fls_cmd.returncode != 0:
                self.log(f"fls failed: {fls_cmd.stderr}")
                self.scan_image_ext4()
                return
            
            current_path = '/'
            for line in fls_cmd.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith('/') and ':' in line:
                    parts = line.split(':', 1)
                    current_path = parts[0].rstrip('/') or '/'
                    continue
                
                match = re.match(r'^([dfrlcpb]+)/([dfrlcpb]+)\s+(\d+):\s+(.+?)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d+)\s+(\d+)\s+(\d+)\s*$', line)
                if match:
                    type1 = match.group(1)
                    type2 = match.group(2)
                    inode = int(match.group(3))
                    name = match.group(4)
                    mtime_str = match.group(5)
                    size = int(match.group(6))
                    uid = int(match.group(7))
                    gid = int(match.group(8))
                    
                    is_dir = type2 == 'd'
                    
                    if name in ['.', '..']:
                        continue
                    
                    try:
                        mtime = datetime.strptime(mtime_str, '%Y-%m-%d %H:%M:%S').timestamp()
                    except:
                        mtime = 0.0
                    
                    full_path = f"{current_path}/{name}" if current_path != '/' else f"/{name}"
                    
                    file_info = {
                        'path': full_path,
                        'inode': inode,
                        'size': size,
                        'mode': '',
                        'atime': mtime,
                        'mtime': mtime,
                        'ctime': mtime,
                        'crtime': 0.0,
                        'is_dir': is_dir,
                        'source': 'fls',
                        'uid': uid,
                        'gid': gid
                    }
                    
                    self.files.append(file_info)
                    self._add_file_stats(full_path, size, is_dir)
                    
                    if not is_dir:
                        self.total_size += size
                        self.file_count += 1
            
            print(f"已發現 {len(self.files)} 個項目，正在獲取 metadata...")
            
            istat_count = 0
            for f in self.files:
                if f.get('is_dir') or istat_count >= 200:
                    continue
                if f.get('inode'):
                    istat_info = self.get_inode_info_istat(f['inode'])
                    if istat_info:
                        f.update(istat_info)
                    istat_count += 1
                if istat_count % 50 == 0:
                    print(f"  已處理 {istat_count} 個檔案...")
            
            print("Metadata 擷取完成")
            
        except FileNotFoundError:
            self.log('fls not found, falling back to debugfs')
            self.scan_image_ext4()
        except Exception as e:
            self.log(f'fls scan failed: {e}')
            self.scan_image_ext4()
    
    def _scan_ext_recursive(self, path: str):
        cmd = ['debugfs', '-R', f'ls -l {path}', str(self.path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.strip().split('\n'):
            match = re.match(r'^\s*(\d+)\s+(\d+)\s+\((\d+)\)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d\w-]+)\s+([\d:]+)\s+(.+)', line)
            if not match:
                continue
            
            inode_str, mode, links, uid, gid, size_str, date, time, name = match.groups()
            name = name.strip()
            
            if name in ['.', '..']:
                continue
            
            try:
                inode = int(inode_str)
                size = int(size_str)
                is_dir = mode.startswith('4')
                full_path = f"{path}/{name}" if path != '/' else f"/{name}"
                
                mtime = 0.0
                try:
                    mtime = datetime.strptime(f"{date} {time}", '%d-%b-%Y %H:%M:%S').timestamp()
                except:
                    pass
                
                file_info = {
                    'path': full_path,
                    'inode': inode,
                    'size': size,
                    'mode': mode,
                    'atime': 0.0,
                    'mtime': mtime,
                    'ctime': 0.0,
                    'crtime': 0.0,
                    'is_dir': is_dir,
                    'source': 'ext4_image'
                }
                
                self.files.append(file_info)
                self._add_file_stats(full_path, size, is_dir)
                if not is_dir:
                    self.total_size += size
                    self.file_count += 1
                
                if is_dir:
                    self._scan_ext_recursive(full_path)
                    
            except (ValueError, IndexError):
                continue
    
    def scan_directory(self):
        print(f"正在掃描: {self.path}")
        
        if self.is_image and self.image_type and self.image_type.startswith('ext'):
            self.scan_with_fls()
            print(f"掃描完成!\n")
            self._build_path_index()
            return
        
        for root, dirs, files in os.walk(self.path):
            root_path = Path(root)
            
            for filename in files:
                filepath = root_path / filename
                try:
                    stat = filepath.stat()
                    
                    file_info = {
                        'path': str(filepath),
                        'inode': stat.st_ino,
                        'size': stat.st_size,
                        'atime': stat.st_atime,
                        'mtime': stat.st_mtime,
                        'ctime': stat.st_ctime,
                        'crtime': 0.0,
                        'is_dir': False,
                        'source': 'filesystem'
                    }
                    
                    self.files.append(file_info)
                    self._add_file_stats(str(filepath), stat.st_size, False)
                    self.total_size += stat.st_size
                    self.file_count += 1
                    
                    self._analyze_file(filepath, file_info)
                    
                except (OSError, PermissionError) as e:
                    self.log(f"無法讀取: {filepath} - {e}")
                    continue
    
    def _add_file_stats(self, path: str, size: int, is_dir: bool):
        if is_dir:
            return
        ext = Path(path).suffix.lower() or '無副檔名'
        self.file_stats[ext]['count'] += 1
        self.file_stats[ext]['size'] += size
    
    def _analyze_file(self, filepath: Path, file_info: Dict):
        name = filepath.name
        path = str(filepath)
        
        severity = Severity.INFO
        reason = ''
        
        for pattern, level, desc in HIGH_PRIORITY_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                severity = level
                reason = f'{desc} (檔名)'
                break
        
        if severity < Severity.HIGH:
            for keyword in CTF_KEYWORDS:
                if keyword.lower() in name.lower():
                    severity = Severity.MEDIUM
                    reason = f'CTF 關鍵字於檔名: {keyword}'
                    break
        
        if severity < Severity.MEDIUM and name.startswith('.'):
            severity = Severity.MEDIUM
            reason = '隱藏檔案'
        
        if severity < Severity.MEDIUM:
            for ext in SUSPICIOUS_EXTENSIONS:
                if name.endswith(ext):
                    severity = Severity.MEDIUM
                    reason = f'可疑副檔名: {ext}'
                    break
        
        if severity >= Severity.MEDIUM:
            finding = self.create_finding(
                file_info, severity, reason, 'filename',
                rule_id='NAME-KEYWORD-001',
                confidence='high' if severity >= Severity.HIGH else 'medium',
                method='path+regex'
            )
            self.findings.append(finding)
    
    def search_in_file_content(self, file_info: Dict, content: bytes) -> List[Dict]:
        results = []
        
        content_lower = content.decode('utf-8', errors='ignore').lower()
        
        for pattern, level, desc in HIGH_PRIORITY_PATTERNS:
            pattern_bytes = pattern.encode('utf-8')
            match = re.search(pattern_bytes, content, re.IGNORECASE)
            if match:
                snippet = content[max(0, match.start()-20):match.end()+20]
                result = self.create_finding(
                    file_info, level, f'{desc} (內容)', 'content',
                    snippet=snippet.decode('utf-8', errors='replace'),
                    rule_id='CONTENT-FLAG-001',
                    confidence='high',
                    evidence_type='content+regex',
                    method='icat+regex'
                )
                try:
                    decoded = base64.b64decode(content[:min(200, len(content))])
                    if len(decoded) > 10:
                        printable_ratio = sum(1 for c in decoded if c >= 32 and c < 127) / len(decoded)
                        if printable_ratio > 0.8:
                            result['decoded'] = decoded.decode('utf-8', errors='replace')[:100]
                except:
                    pass
                results.append(result)
                break
        
        if not results:
            for keyword in CTF_KEYWORDS:
                if keyword.lower() in content_lower:
                    idx = content_lower.find(keyword.lower())
                    snippet = content[max(0, idx-15):idx+len(keyword)+15]
                    result = self.create_finding(
                        file_info, Severity.LOW, f'CTF 關鍵字: {keyword}', 'content',
                        snippet=snippet.decode('utf-8', errors='replace'),
                        rule_id='CONTENT-KEYWORD-001',
                        confidence='medium',
                        evidence_type='content+keyword',
                        method='icat+string'
                    )
                    results.append(result)
                    break
        
        return results
    
    def search_strings_in_file(self, file_info: Dict, data: bytes, min_len: int = 6) -> List[Dict]:
        results = []
        
        strings = re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)
        
        for s in strings:
            s_decoded = s.decode('ascii', errors='ignore')
            
            for pattern, level, desc in HIGH_PRIORITY_PATTERNS:
                pattern_bytes = pattern.encode('utf-8')
                if re.search(pattern_bytes, s, re.IGNORECASE):
                    result = self.create_finding(
                        file_info, level, f'{desc} (字串)', 'strings',
                        snippet=s_decoded[:100],
                        rule_id='STRINGS-FLAG-001',
                        confidence='high',
                        evidence_type='strings+regex',
                        method='strings+regex'
                    )
                    results.append(result)
                    break
            
            if not any(r.get('snippet') == s_decoded[:100] for r in results):
                for keyword in CTF_KEYWORDS:
                    if keyword.lower() in s_decoded.lower():
                        result = self.create_finding(
                            file_info, Severity.MEDIUM, f'關鍵字: {keyword}', 'strings',
                            snippet=s_decoded[:100],
                            rule_id='STRINGS-KEYWORD-001',
                            confidence='medium',
                            evidence_type='strings+keyword',
                            method='strings+grep'
                        )
                        results.append(result)
                        break
        
        return results
    
    def detect_file_type(self, data: bytes, path: str) -> Optional[str]:
        for magic, file_type in MAGIC_BYTES.items():
            if data.startswith(magic):
                return file_type
        
        if data.startswith(b'\x00') and len(set(data[:100])) < 5:
            return 'Binary/null-padded'
        
        printable = sum(1 for b in data[:1000] if 32 <= b <= 126)
        if printable / min(len(data), 1000) > 0.85:
            return 'Text'
        
        return None
    
    def calculate_hash(self, data: bytes) -> Dict[str, str]:
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / len(data)
                entropy -= p * math.log2(p)
        return entropy
    
    def analyze_files(self, max_size: int = 5*1024*1024):
        print("正在分析檔案內容...")
        
        file_count = 0
        for file_info in self.files:
            if file_info.get('is_dir') or file_info['size'] == 0:
                continue
            
            if file_info['size'] > max_size:
                continue
            
            file_count += 1
            if file_count % 500 == 0:
                print(f"  已分析 {file_count} 個檔案...")
            
            data = None
            
            if self.is_image and self.image_type and self.image_type.startswith('ext'):
                if file_info['size'] <= max_size:
                    data = self.read_file_from_image(file_info['inode'])
            elif file_info['source'] == 'filesystem':
                try:
                    with open(file_info['path'], 'rb') as f:
                        data = f.read(max_size)
                except:
                    continue
            
            if not data:
                continue
            
            content_results = self.search_in_file_content(file_info, data)
            for r in content_results:
                if not self._is_duplicate_finding(r):
                    self.findings.append(r)
            
            strings_results = self.search_strings_in_file(file_info, data)
            for r in strings_results:
                if not self._is_duplicate_finding(r):
                    self.findings.append(r)
            
            detected_type = self.detect_file_type(data, file_info['path'])
            if detected_type:
                ext = Path(file_info['path']).suffix.lower()
                if ext:
                    expected_types = EXTENSION_MAGIC_MAPPING.get(ext, [])
                    if expected_types and detected_type not in expected_types:
                        severity = Severity.LOW
                        rule_id = 'MISMATCH-001'
                        
                        key = (ext, detected_type)
                        if key in EXTENSION_MISMATCH_SEVERITY:
                            severity = EXTENSION_MISMATCH_SEVERITY[key]
                            rule_id = f'MISMATCH-{ext[1:].upper()}-001'
                        
                        finding = self.create_finding(
                            file_info, severity,
                            f'類型不符: 實際為 {detected_type}, 副檔名為 {ext}',
                            'type_mismatch',
                            rule_id=rule_id,
                            evidence_type='magic_mismatch',
                            confidence='high' if severity >= Severity.HIGH else 'medium',
                            method='icat+magic'
                        )
                        self.findings.append(finding)
        
        print(f"內容分析完成，共發現 {len(self.findings)} 個 findings")
    
    def _is_duplicate_finding(self, new_finding: Dict) -> bool:
        new_rule_id = new_finding.get('rule_id', 'GENERIC-001')
        new_snippet = new_finding.get('snippet', '')
        new_path = new_finding.get('path', '')
        
        for existing in self.findings:
            if existing.get('path') != new_path:
                continue
            
            if existing.get('rule_id') != new_rule_id:
                continue
            
            if existing.get('snippet') == new_snippet:
                return True
        return False
    
    def analyze_suspicious_paths(self):
        print("正在分析可疑路徑...")
        
        for file_info in self.files:
            if file_info.get('is_dir'):
                continue
            
            path = file_info['path']
            severity = Severity.INFO
            reason = ''
            
            for critical_path in CRITICAL_PATHS:
                if path.startswith(critical_path):
                    if file_info['size'] < 10240:
                        severity = Severity.HIGH
                        reason = f'{critical_path} 下小檔案'
                    else:
                        severity = Severity.MEDIUM
                        reason = f'{critical_path} 路徑'
                    break
            
            name = Path(path).name
            if name in ['.bash_history', '.ash_history', '.viminfo', '.mysql_history']:
                severity = max(severity, Severity.HIGH)
                reason = 'Shell history 檔案'
            
            if name.endswith('.log') or name.endswith('.txt'):
                if severity >= Severity.MEDIUM:
                    finding = self.create_finding(
                        file_info, severity, reason + ' + 可疑檔案類型', 'suspicious_path',
                        rule_id='PATH-SUSP-001',
                        confidence='high' if severity >= Severity.HIGH else 'medium',
                        evidence_type='path+extension',
                        method='path+heuristic'
                    )
                    self.findings.append(finding)
    
    def build_timeline(self):
        self.timeline = sorted(self.files, 
                              key=lambda x: x.get('mtime', 0), 
                              reverse=True)
        return self.timeline
    
    def analyze_time_correlations(self, time_window: int = 120):
        print(f"正在分析時間關聯性 (窗口: {time_window}秒)...")
        
        file_list = [f for f in self.files if not f.get('is_dir') and f.get('mtime', 0) > 0]
        file_list.sort(key=lambda x: x['mtime'])
        
        significant_times = []
        
        if not file_list:
            return significant_times
        
        current_group = [file_list[0]]
        
        for i in range(1, len(file_list)):
            prev_file = file_list[i - 1]
            curr_file = file_list[i]
            
            time_diff = curr_file['mtime'] - prev_file['mtime']
            
            if time_diff <= time_window:
                current_group.append(curr_file)
            else:
                if len(current_group) > 1:
                    avg_time = sum(x['mtime'] for x in current_group) / len(current_group)
                    significant_times.append({
                        'time': avg_time,
                        'time_window': time_window,
                        'count': len(current_group),
                        'files': current_group,
                        'time_range': (min(x['mtime'] for x in current_group), max(x['mtime'] for x in current_group))
                    })
                current_group = [curr_file]
        
        if len(current_group) > 1:
            avg_time = sum(x['mtime'] for x in current_group) / len(current_group)
            significant_times.append({
                'time': avg_time,
                'time_window': time_window,
                'count': len(current_group),
                'files': current_group,
                'time_range': (min(x['mtime'] for x in current_group), max(x['mtime'] for x in current_group))
            })
        
        significant_times.sort(key=lambda x: x['count'], reverse=True)
        
        print(f"發現 {len(significant_times)} 個時間群組")
        return significant_times
    
    def deep_analyze_suspicious_files(self):
        print("正在深度分析可疑檔案...")
        
        standard_etc_files = {
            'passwd', 'shadow', 'group', 'hosts', 'resolv.conf', 'hostname',
            'nsswitch.conf', 'services', 'protocols', 'motd', 'profile',
            'shells', 'ld.so.conf', 'mtab', 'fstab', 'issue', 'os-release'
        }
        
        critical_paths = ['/etc/', '/root/', '/tmp/', '/var/tmp/', '/home/']
        
        recent_files = sorted(
            [f for f in self.files if not f.get('is_dir') and f.get('mtime', 0) > 0],
            key=lambda x: x.get('mtime', 0),
            reverse=True
        )[:50]
        recent_mtime_threshold = recent_files[-1].get('mtime', 0) if recent_files else 0
        
        for file_info in self.files:
            if file_info.get('is_dir'):
                continue
            
            path = file_info['path']
            name = Path(path).name
            reasons = []
            severity = Severity.INFO
            mtime = file_info.get('mtime', 0)
            size = file_info.get('size', 0)
            
            if any(path.startswith(wp) for wp in WHITELIST_PATHS):
                continue
            
            if path.startswith('/etc/') and name in standard_etc_files:
                continue
            
            in_critical_path = any(path.startswith(cp) for cp in critical_paths)
            
            if name in ['chat', 'secret', 'flag', 'password']:
                severity = Severity.HIGH
                reasons.append('suspicious filename')
            
            if in_critical_path and mtime >= recent_mtime_threshold:
                severity = max(severity, Severity.HIGH)
                reasons.append('very recent modification')
            
            if size < 4096 and size > 0:
                reasons.append('small file')
            
            inode = file_info.get('inode')
            content = None
            decoded_content = None
            
            if not file_info.get('is_dir') and size > 0 and size < 10240 and inode:
                if self.is_image and self.image_type and self.image_type.startswith('ext'):
                    data = self.read_file_from_image(int(inode))
                    if data:
                        try:
                            content = data.decode('utf-8', errors='replace')
                        except:
                            content = None
                        
                        if content:
                            decoded_content = self._verify_base64_content(content)
                            
                            if decoded_content:
                                reasons.append('valid base64-encoded content')
                                printable_ratio = sum(1 for c in decoded_content if c.isprintable()) / max(len(decoded_content), 1)
                                if printable_ratio > 0.7:
                                    reasons.append('decoded content is mostly printable')
                            
                            for pattern, level, desc in HIGH_PRIORITY_PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    if level > severity:
                                        severity = level
                                    reasons.append(f'{desc} pattern in content')
                                    break
                            
                            if decoded_content:
                                for pattern, level, desc in HIGH_PRIORITY_PATTERNS:
                                    if re.search(pattern, decoded_content, re.IGNORECASE):
                                        if level > severity:
                                            severity = level
                                        reasons.append(f'decoded content: {desc}')
                                        break
            
            if severity >= Severity.HIGH and reasons:
                stat_info = self.get_file_stat(int(inode)) if inode else None
                finding = self.create_finding(
                    file_info, severity, '; '.join(reasons), 'suspicious_analysis',
                    reasons=reasons,
                    content=content[:100] if content else None,
                    decoded=decoded_content[:100] if decoded_content else None,
                    metadata=stat_info,
                    rule_id='SUSP-DEEP-001',
                    confidence='high',
                    evidence_type='path+time+content',
                    method='icat+regex+heuristic'
                )
                self.findings.append(finding)
    
    def _verify_base64_content(self, content: str) -> Optional[str]:
        content = content.strip()
        
        if len(content) < 4:
            return None
        
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='replace')
        except:
            return None
        
        printable = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
        if len(decoded) > 0 and printable / len(decoded) > 0.8:
            return decoded
        return None
    
    def verify_base64_quality(self, content: str) -> Optional[Dict]:
        content = content.strip()
        if len(content) < 8:
            return None
        
        try:
            decoded = base64.b64decode(content).decode('utf-8', errors='replace')
        except:
            return None
        
        if not decoded:
            return None
        
        printable_count = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
        printable_ratio = printable_count / len(decoded) if len(decoded) > 0 else 0
        
        if printable_ratio < 0.8:
            return None
        
        valid_chars = sum(1 for c in decoded if c.isalnum() or c in '_-{}')
        valid_ratio = valid_chars / len(decoded) if len(decoded) > 0 else 0
        
        if valid_ratio < 0.6:
            return None
        
        return {
            'decoded': decoded,
            'printable_ratio': printable_ratio,
            'valid_ratio': valid_ratio,
            'length': len(decoded)
        }
    
    def is_flag_like(self, content: str) -> bool:
        if not content:
            return False
        
        content = content.strip()
        content_lower = content.lower()
        
        if 'picoctf{' in content_lower or 'flag{' in content_lower:
            return True
        
        if not (12 <= len(content) <= 80):
            return False
        
        allowed_ratio = sum(
            1 for c in content if c.isalnum() or c in '_-{}'
        ) / len(content)
        
        has_alpha = any(c.isalpha() for c in content)
        has_digit = any(c.isdigit() for c in content)
        has_sep = any(c in '_-' for c in content)
        
        if allowed_ratio < 0.9:
            return False
        
        if has_alpha and has_digit and has_sep:
            return True
        
        return False
    
    def format_flag_candidate(self, decoded: str) -> str:
        decoded = (decoded or '').strip()
        if not decoded:
            return ''
        
        if re.fullmatch(r'picoCTF\{[^}]+\}', decoded, re.IGNORECASE):
            return decoded
        
        if re.fullmatch(r'flag\{[^}]+\}', decoded, re.IGNORECASE):
            return decoded
        
        return f'picoCTF{{{decoded}}}'
    
    def score_oldest_suspicious(self, f: Dict) -> float:
        score = 0.0
        
        files = [x for x in self.files if not x.get('is_dir') and x.get('mtime', 0) > 0]
        if not files:
            return 0.0
        
        mtimes = sorted(x['mtime'] for x in files)
        median = mtimes[len(mtimes)//2]
        days_older = (median - f.get('mtime', 0)) / 86400
        score += min(days_older / 100, 50)
        
        size = f.get('size', 0)
        if size <= 64:
            score += 30
        elif size <= 128:
            score += 20
        elif size <= 512:
            score += 10
        
        path = f.get('path', '')
        if any(path.startswith(p) for p in HIGH_PRIORITY_PATHS):
            score += 25
        elif any(path.startswith(p) for p in MEDIUM_PRIORITY_PATHS):
            score += 10
        
        name = Path(path).name
        if name in ['chat', 'secret', 'flag', 'password', 'pass', 'key', 'bcab']:
            score += 30
        elif not Path(path).suffix and len(name) < 10:
            score += 10
        
        if any(path.startswith(wl) for wl in SUSPICIOUS_WHITELIST):
            score -= 50
        
        decoded = f.get('decoded')
        if decoded:
            if self.is_flag_like(decoded):
                score += 50
            elif f.get('base64_quality', {}).get('valid_ratio', 0) > 0.8:
                score += 20
        
        return score
    
    def score_newest_suspicious(self, f: Dict) -> float:
        score = 0.0
        
        recent_files = sorted(
            [x for x in self.files if not x.get('is_dir') and x.get('mtime', 0) > 0],
            key=lambda x: x.get('mtime', 0),
            reverse=True
        )[:50]
        
        if recent_files:
            for i, rf in enumerate(recent_files):
                if rf.get('path') == f.get('path'):
                    score += (50 - i)
                    break
        
        size = f.get('size', 0)
        if size <= 64:
            score += 30
        elif size <= 128:
            score += 20
        elif size <= 512:
            score += 10
        
        path = f.get('path', '')
        if any(path.startswith(p) for p in HIGH_PRIORITY_PATHS):
            score += 25
        elif any(path.startswith(p) for p in MEDIUM_PRIORITY_PATHS):
            score += 10
        
        name = Path(path).name
        if name in ['chat', 'secret', 'flag', 'password', 'pass', 'key']:
            score += 30
        elif not Path(path).suffix and len(name) < 10:
            score += 10
        
        if any(path.startswith(wl) for wl in SUSPICIOUS_WHITELIST):
            score -= 50
        
        decoded = f.get('decoded')
        if decoded:
            if self.is_flag_like(decoded):
                score += 50
            elif f.get('base64_quality', {}).get('valid_ratio', 0) > 0.8:
                score += 20
        
        return score
    
    def find_readable_decoded_payloads(self, max_size: int = 512) -> List[Dict]:
        if self.cached_decoded_payloads is not None:
            return self.cached_decoded_payloads
        
        results = []
        
        small_files = [f for f in self.files if not f.get('is_dir') and f.get('size', 0) <= max_size]
        
        for f in small_files:
            inode = f.get('inode')
            if not inode or not self.is_image:
                continue
            
            data = self.read_file_from_image(int(inode))
            if not data:
                continue
            
            content = None
            try:
                content = data.decode('utf-8', errors='replace')
            except:
                continue
            
            b64q = self.verify_base64_quality(content)
            if b64q:
                decoded = b64q['decoded']
                if self.is_flag_like(decoded):
                    score = self._score_payload(f, decoded, b64q)
                    results.append({
                        **f,
                        'decoded': decoded,
                        'reason': 'flag-like decoded',
                        'quality': b64q,
                        'score': score
                    })
                    continue
            
            candidates = self.extract_base64_candidates(content)
            for c in candidates[:5]:
                b64q = self.verify_base64_quality(c)
                if b64q:
                    decoded = b64q['decoded']
                    if self.is_flag_like(decoded):
                        score = self._score_payload(f, decoded, b64q)
                        results.append({
                            **f,
                            'decoded': decoded,
                            'reason': 'flag-like in candidates',
                            'quality': b64q,
                            'score': score
                        })
                        break
        
        self.cached_decoded_payloads = sorted(results, key=lambda x: x.get('score', 0), reverse=True)
        return self.cached_decoded_payloads
    
    def _score_payload(self, f: Dict, decoded: str, b64q: Dict) -> float:
        score = 0.0
        path = f.get('path', '')
        
        if 'picoctf{' in decoded.lower() or 'flag{' in decoded.lower():
            score += 50
        
        if any(path.startswith(p) for p in HIGH_PRIORITY_PATHS):
            score += 20
        
        size = f.get('size', 0)
        if size <= 64:
            score += 15
        elif size <= 256:
            score += 10
        
        score += b64q.get('valid_ratio', 0) * 15
        
        entropy = self.calculate_entropy(decoded.encode() if decoded else b'')
        if 2.0 <= entropy <= 5.0:
            score += 10
        
        if not Path(path).suffix:
            score += 5
        
        return score
    
    def extract_base64_candidates(self, content: str) -> List[str]:
        candidates = []
        for line in content.splitlines():
            s = line.strip()
            if len(s) >= 8 and re.fullmatch(r'[A-Za-z0-9+/=]+', s):
                candidates.append(s)
        return candidates
    
    def find_time_outliers(self) -> List[Dict]:
        if self.cached_time_outliers is not None:
            return self.cached_time_outliers
        
        files = [f for f in self.files if not f.get('is_dir') and f.get('mtime', 0) > 0]
        if not files:
            return []
        
        mtimes = sorted(f['mtime'] for f in files)
        median = mtimes[len(mtimes)//2]
        
        outliers = []
        for f in files:
            diff = median - f['mtime']
            if diff > 60 * 60 * 24 * 30:
                outliers.append({
                    **f,
                    'time_delta': diff,
                    'median_ts': median
                })
        
        self.cached_time_outliers = sorted(outliers, key=lambda x: x['mtime'])
        return self.cached_time_outliers
    
    def analyze_time_outliers_content(self, outliers: List[Dict]) -> List[Dict]:
        results = []
        
        for f in outliers:
            if f['size'] >= 4096:
                continue
            
            inode = f.get('inode')
            if not inode:
                continue
            
            data = self.read_file_from_image(int(inode))
            if not data:
                continue
            
            content = None
            try:
                content = data.decode('utf-8', errors='replace')
            except:
                continue
            
            decoded = None
            base64_candidates = self.extract_base64_candidates(content)
            
            for candidate in base64_candidates[:3]:
                decoded = self._verify_base64_content(candidate)
                if decoded:
                    break
            
            if not decoded:
                decoded = self._verify_base64_content(content)
            
            flag_pattern = re.compile(r'picoCTF\{[^}]+\}', re.IGNORECASE)
            flag_match = flag_pattern.search(content)
            if flag_match:
                f['flag_found'] = flag_match.group(0)
            
            if decoded:
                flag_match_decoded = flag_pattern.search(decoded)
                if flag_match_decoded:
                    f['flag_found'] = flag_match_decoded.group(0)
            
            f['decoded'] = decoded[:80] if decoded else None
            f['has_base64'] = len(base64_candidates) > 0
            f['base64_candidates_count'] = len(base64_candidates)
            
            results.append(f)
        
        return results
    
    def find_recent_suspicious_small_files(self) -> List[Dict]:
        if self.cached_recent_suspicious is not None:
            return self.cached_recent_suspicious
        
        suspicious_paths = ['/etc/', '/root/', '/tmp/', '/var/tmp/', '/home/']
        
        recent_files = sorted(
            [f for f in self.files if not f.get('is_dir') and f.get('mtime', 0) > 0],
            key=lambda x: x.get('mtime', 0),
            reverse=True
        )[:50]
        
        if not recent_files:
            return []
        
        threshold_time = recent_files[-1].get('mtime', 0)
        
        results = []
        for f in self.files:
            if f.get('is_dir'):
                continue
            
            path = f.get('path', '')
            size = f.get('size', 0)
            mtime = f.get('mtime', 0)
            
            if mtime < threshold_time:
                continue
            
            if size >= 256:
                continue
            
            if not any(path.startswith(sp) for sp in suspicious_paths):
                continue
            
            if any(path.startswith(wl) for wl in SUSPICIOUS_WHITELIST):
                continue
            
            if path in SYSTEM_WHITELIST:
                continue
            
            name = Path(path).name
            if name in ['.', '..'] or name.startswith('.'):
                continue
            
            reasons = []
            
            if size < 128:
                reasons.append('small file (<128B)')
            elif size < 256:
                reasons.append('medium file (<256B)')
            
            inode = f.get('inode')
            content = None
            decoded = None
            is_readable = False
            base64_quality = None
            
            if inode and self.is_image:
                data = self.read_file_from_image(int(inode))
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        is_readable = True
                        reasons.append('readable text')
                    except:
                        pass
                    
                    if content:
                        base64_quality = self.verify_base64_quality(content)
                        if base64_quality:
                            decoded = base64_quality['decoded']
                            reasons.append(f'base64 (valid={base64_quality["valid_ratio"]:.1%})')
                        
                        if not decoded:
                            candidates = self.extract_base64_candidates(content)
                            for c in candidates[:3]:
                                b64q = self.verify_base64_quality(c)
                                if b64q:
                                    decoded = b64q['decoded']
                                    break
                        
                        flag_pattern = re.compile(r'picoCTF\{[^}]+\}', re.IGNORECASE)
                        if flag_pattern.search(content):
                            reasons.append('picoCTF flag in content')
                        elif decoded and flag_pattern.search(decoded):
                            reasons.append('picoCTF flag in decoded')
            
            if is_readable and (decoded or (content and len(content.strip()) > 0)):
                results.append({
                    **f,
                    'reasons': reasons,
                    'content': content[:100] if content else None,
                    'decoded': decoded[:80] if decoded else None,
                    'is_readable': is_readable,
                    'base64_quality': base64_quality
                })
        
        self.cached_recent_suspicious = results
        return self.cached_recent_suspicious
    
    def find_oldest_suspicious_small_files(self) -> List[Dict]:
        if self.cached_oldest_suspicious is not None:
            return self.cached_oldest_suspicious
        
        old_files = sorted(
            [f for f in self.files if not f.get('is_dir') and f.get('mtime', 0) > 0],
            key=lambda x: x.get('mtime', 0)
        )[:50]
        
        if not old_files:
            return []
        
        threshold_time = old_files[-1].get('mtime', 0)
        
        results = []
        for f in self.files:
            if f.get('is_dir'):
                continue
            
            path = f.get('path', '')
            size = f.get('size', 0)
            mtime = f.get('mtime', 0)
            
            if mtime > threshold_time:
                continue
            
            if size >= 256:
                continue
            
            if any(path.startswith(wl) for wl in SUSPICIOUS_WHITELIST):
                continue
            
            if path in SYSTEM_WHITELIST:
                continue
            
            name = Path(path).name
            if name in ['.', '..'] or name.startswith('.'):
                continue
            
            reasons = []
            
            if size < 128:
                reasons.append('small file (<128B)')
            elif size < 256:
                reasons.append('medium file (<256B)')
            
            inode = f.get('inode')
            content = None
            decoded = None
            is_readable = False
            base64_quality = None
            
            if inode and self.is_image:
                data = self.read_file_from_image(int(inode))
                if data:
                    try:
                        content = data.decode('utf-8', errors='replace')
                        is_readable = True
                        reasons.append('readable text')
                    except:
                        pass
                    
                    if content:
                        base64_quality = self.verify_base64_quality(content)
                        if base64_quality:
                            decoded = base64_quality['decoded']
                            reasons.append(f'base64 (valid={base64_quality["valid_ratio"]:.1%})')
                        
                        if not decoded:
                            candidates = self.extract_base64_candidates(content)
                            for c in candidates[:3]:
                                b64q = self.verify_base64_quality(c)
                                if b64q:
                                    decoded = b64q['decoded']
                                    break
                        
                        flag_pattern = re.compile(r'picoCTF\{[^}]+\}', re.IGNORECASE)
                        if flag_pattern.search(content):
                            reasons.append('picoCTF flag in content')
                        elif decoded and flag_pattern.search(decoded):
                            reasons.append('picoCTF flag in decoded')
            
            if is_readable and (decoded or (content and len(content.strip()) > 0)):
                results.append({
                    **f,
                    'reasons': reasons,
                    'content': content[:100] if content else None,
                    'decoded': decoded[:80] if decoded else None,
                    'is_readable': is_readable,
                    'base64_quality': base64_quality
                })
        
        self.cached_oldest_suspicious = sorted(results, key=lambda x: x.get('mtime', 0))
        return self.cached_oldest_suspicious
    
    def decode_findings_base64(self):
        decoded_count = 0
        for f in self.findings:
            if f.get('content') and not f.get('decoded'):
                try:
                    decoded = base64.b64decode(f['content'][:200])
                    printable = sum(1 for c in decoded if c >= 32 and c < 127) / len(decoded)
                    if printable > 0.8:
                        f['decoded'] = decoded.decode('utf-8', errors='replace')[:100]
                        decoded_count += 1
                except:
                    pass
        return decoded_count
    
    def export_timeline_csv(self, output: str = 'timeline.csv'):
        print(f"匯出時間線至 {output}...")
        
        with open(output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Path', 'Size', 'ATime', 'MTime', 'CTime', 'CRTime', 
                          'Inode', 'Is_Dir', 'Source'])
            
            for file_info in self.timeline:
                writer.writerow([
                    file_info['path'],
                    file_info['size'],
                    self.format_time(file_info.get('atime', 0)),
                    self.format_time(file_info.get('mtime', 0)),
                    self.format_time(file_info.get('ctime', 0)),
                    self.format_time(file_info.get('crtime', 0)),
                    file_info.get('inode', ''),
                    file_info.get('is_dir', False),
                    file_info.get('source', 'filesystem')
                ])
        
        print(f"已匯出 {len(self.timeline)} 筆記錄")
    
    def export_findings_json(self, output: str = 'findings.json'):
        print(f"匯出 findings 至 {output}...")
        
        findings_export = []
        for f in self.findings:
            findings_export.append({
                'path': f.get('path'),
                'inode': f.get('inode'),
                'size': f.get('size'),
                'mtime': f.get('mtime'),
                'atime': f.get('atime'),
                'ctime': f.get('ctime'),
                'crtime': f.get('crtime'),
                'is_dir': f.get('is_dir'),
                'source': f.get('source'),
                'severity': f.get('severity'),
                'severity_name': self.get_severity_name(f.get('severity', 0)),
                'reason': f.get('reason'),
                'category': f.get('category'),
                'rule_id': f.get('rule_id'),
                'confidence': f.get('confidence'),
                'evidence_type': f.get('evidence_type'),
                'method': f.get('method'),
                'snippet': f.get('snippet'),
                'decoded': f.get('decoded'),
                'content': f.get('content')[:200] if f.get('content') else None,
            })
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(findings_export, f, indent=2, default=str)
        
        print(f"已匯出 {len(findings_export)} 個 findings")
    
    def export_summary_json(self, output: str = 'summary.json', analysis_options: Optional[Dict] = None):
        print(f"匯出摘要至 {output}...")
        
        high_count = len([f for f in self.findings if f.get('severity', 0) >= Severity.HIGH])
        med_count = len([f for f in self.findings if f.get('severity', 0) == Severity.MEDIUM])
        low_count = len([f for f in self.findings if f.get('severity', 0) == Severity.LOW])
        
        decoded_payloads = self.find_readable_decoded_payloads()
        
        if analysis_options is None:
            analysis_options = {}
        
        summary = {
            'version': VERSION,
            'scan_info': {
                'path': str(self.path),
                'is_image': self.is_image,
                'image_type': self.image_type,
                'scan_time': datetime.now().isoformat(),
            },
            'statistics': {
                'total_files': self.file_count,
                'total_size': self.total_size,
                'total_items': len(self.files),
            },
            'findings_summary': {
                'high_risk': high_count,
                'medium_risk': med_count,
                'low_risk': low_count,
                'total': len(self.findings),
            },
            'findings_by_rule': defaultdict(int),
            'findings_by_category': defaultdict(int),
            'findings_by_method': defaultdict(int),
            'decoded_payloads_count': len(decoded_payloads),
            'file_type_distribution': dict(self.file_stats),
            'export_info': self.build_export_info(),
            'session_info': self.build_session_info(analysis_options),
        }
        
        for f in self.findings:
            rule_id = f.get('rule_id', 'UNKNOWN')
            category = f.get('category', 'unknown')
            method = f.get('method', 'unknown')
            summary['findings_by_rule'][rule_id] += 1
            summary['findings_by_category'][category] += 1
            summary['findings_by_method'][method] += 1
        
        summary['findings_by_rule'] = dict(summary['findings_by_rule'])
        summary['findings_by_category'] = dict(summary['findings_by_category'])
        summary['findings_by_method'] = dict(summary['findings_by_method'])
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
        
        print(f"已匯出摘要至 {output}")
    
    def export_payloads_json(self, output: str = 'decoded_payloads.json'):
        print(f"匯出 decoded payloads 至 {output}...")
        
        payloads = self.find_readable_decoded_payloads()
        
        payloads_export = []
        for p in payloads:
            payloads_export.append(self.serialize_payload(p))
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(payloads_export, f, indent=2, default=str)
        
        print(f"已匯出 {len(payloads_export)} 個 decoded payloads")
    
    def export_artifacts(self, output_dir: str = 'artifacts'):
        print(f"匯出 artifacts 至 {output_dir}/...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        decoded_payloads = self.find_readable_decoded_payloads()
        
        payloads_dir = os.path.join(output_dir, 'decoded_payloads')
        os.makedirs(payloads_dir, exist_ok=True)
        
        for i, p in enumerate(decoded_payloads[:50], 1):
            decoded = p.get('decoded', '')
            if decoded:
                safe_name = self.sanitize_filename(p.get('path', f'payload_{i}'))
                with open(os.path.join(payloads_dir, f'{i:03d}_{safe_name}.txt'), 'w', encoding='utf-8') as f:
                    f.write(decoded)
        
        findings_dir = os.path.join(output_dir, 'findings')
        os.makedirs(findings_dir, exist_ok=True)
        
        high_findings = [f for f in self.findings if f.get('severity', 0) >= Severity.HIGH]
        for i, f in enumerate(high_findings[:50], 1):
            content = f.get('decoded') or f.get('content') or f.get('snippet') or ''
            if content:
                safe_name = self.sanitize_filename(f.get('path', f'finding_{i}'))
                with open(os.path.join(findings_dir, f'{i:03d}_{safe_name}.txt'), 'w', encoding='utf-8') as f:
                    f.write(content)
        
        payload_manifest = []
        for i, p in enumerate(decoded_payloads[:50], 1):
            safe_name = self.sanitize_filename(p.get('path', f'payload_{i}'))
            payload_meta = self.serialize_payload(p)
            payload_manifest.append({
                'index': i,
                'filename': f'{i:03d}_{safe_name}.txt',
                'original_path': payload_meta['path'],
                'inode': payload_meta['inode'],
                'size': payload_meta['size'],
                'type': 'decoded_payload',
                'confidence': payload_meta['confidence'],
                'method': payload_meta['method'],
                'source': payload_meta['source'],
                'mtime': payload_meta['mtime'],
                'reason': payload_meta.get('reason'),
                'score': payload_meta.get('score'),
            })
        
        findings_manifest = []
        high_findings = [f for f in self.findings if f.get('severity', 0) >= Severity.HIGH]
        for i, f in enumerate(high_findings[:50], 1):
            safe_name = self.sanitize_filename(f.get('path', f'finding_{i}'))
            findings_manifest.append({
                'index': i,
                'filename': f'{i:03d}_{safe_name}.txt',
                'original_path': f.get('path'),
                'inode': f.get('inode'),
                'type': 'finding',
                'severity': self.get_severity_name(f.get('severity', 0)),
                'rule_id': f.get('rule_id'),
                'confidence': f.get('confidence'),
                'method': f.get('method'),
                'source': f.get('source'),
                'mtime': f.get('mtime'),
                'reason': f.get('reason'),
            })
        
        manifest = {
            'version': VERSION,
            'generated_at': datetime.now().isoformat(),
            'payloads_count': len(payload_manifest),
            'findings_count': len(findings_manifest),
            'payloads': payload_manifest,
            'findings': findings_manifest,
        }
        
        with open(os.path.join(output_dir, 'manifest.json'), 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, default=str)
        
        print(f"  已匯出 {len(os.listdir(payloads_dir))} 個 decoded payloads")
        print(f"  已匯出 {len(os.listdir(findings_dir))} 個 high-risk findings")
        print(f"  已匯出 manifest.json")
        print(f"Artifacts 已匯出至 {output_dir}/")
    
    def export_all_json(self, output: str = 'scan_result.json', timeline_limit: int = DEFAULT_FULL_EXPORT_TIMELINE_LIMIT, analysis_options: Optional[Dict] = None):
        print(f"匯出完整 JSON 至 {output}...")
        
        high_count = len([f for f in self.findings if f.get('severity', 0) >= Severity.HIGH])
        med_count = len([f for f in self.findings if f.get('severity', 0) == Severity.MEDIUM])
        low_count = len([f for f in self.findings if f.get('severity', 0) == Severity.LOW])
        
        decoded_payloads = self.find_readable_decoded_payloads()
        
        findings_export = []
        for f in self.findings:
            findings_export.append({
                'path': f.get('path'),
                'inode': f.get('inode'),
                'size': f.get('size'),
                'mtime': f.get('mtime'),
                'atime': f.get('atime'),
                'ctime': f.get('ctime'),
                'crtime': f.get('crtime'),
                'severity': f.get('severity'),
                'severity_name': self.get_severity_name(f.get('severity', 0)),
                'reason': f.get('reason'),
                'category': f.get('category'),
                'rule_id': f.get('rule_id'),
                'confidence': f.get('confidence'),
                'evidence_type': f.get('evidence_type'),
                'method': f.get('method'),
                'snippet': f.get('snippet'),
                'decoded': f.get('decoded'),
                'content': f.get('content')[:200] if f.get('content') else None,
            })
        
        payloads_export = []
        for p in decoded_payloads:
            payloads_export.append(self.serialize_payload(p))
        
        full_export = {
            'version': VERSION,
            'scan_info': {
                'path': str(self.path),
                'is_image': self.is_image,
                'image_type': self.image_type,
                'partition_offset': self.partition_offset,
                'scan_time': datetime.now().isoformat(),
            },
            'statistics': {
                'total_files': self.file_count,
                'total_size': self.total_size,
                'total_items': len(self.files),
            },
            'findings_summary': {
                'high_risk': high_count,
                'medium_risk': med_count,
                'low_risk': low_count,
                'total': len(self.findings),
            },
            'decoded_payloads_count': len(decoded_payloads),
            'file_type_distribution': dict(self.file_stats),
            'export_info': self.build_export_info(),
            'findings': findings_export,
            'decoded_payloads': payloads_export,
            'timeline': self.timeline[:timeline_limit],
            'timeline_exported': min(timeline_limit, len(self.timeline)),
            'timeline_total': len(self.timeline),
            'session_info': self.build_session_info(analysis_options),
        }
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(full_export, f, indent=2, default=str)
        
        print(f"已匯出完整 JSON 至 {output}")
    
    def export_timeline_json(self, output: str = 'timeline.json', limit: Optional[int] = None):
        timeline_data = self.timeline if limit is None else self.timeline[:limit]
        print(f"匯出時間線至 {output} (limit={limit})...")
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(timeline_data, f, indent=2, default=str)
        
        print(f"已匯出 {len(timeline_data)} 筆記錄 (total={len(self.timeline)})")
    
    def generate_report(self, output: Optional[str] = None) -> str:
        report = []
        report.append("=" * 70)
        report.append("           CTF 磁碟鑑識分析報告 v4.0-rc1")
        report.append("=" * 70)
        report.append(f"\n分析路徑: {self.path}")
        report.append(f"映像檔模式: {'是' if self.is_image else '否'} ({self.image_type or 'N/A'})")
        if self.partition_offset > 0:
            report.append(f"分割區偏移: {self.partition_offset} bytes ({self.partition_offset // 512} sectors)")
        report.append(f"分析時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        report.append(f"\n{'─' * 70}")
        report.append("【基本統計】")
        report.append(f"{'─' * 70}")
        report.append(f"  總檔案數:     {self.file_count:,}")
        report.append(f"  總大小:       {self.format_size(self.total_size)}")
        report.append(f"  總項目數:     {len(self.files):,}")
        
        decoded_payloads = self.find_readable_decoded_payloads()
        if decoded_payloads:
            report.append(f"\n{'─' * 70}")
            report.append("【FLAG Candidates】")
            report.append(f"{'─' * 70}")
            for i, f in enumerate(decoded_payloads, 1):
                flag = self.format_flag_candidate(f.get('decoded', ''))
                if flag:
                    report.append(f"  {i}. {flag}")
        
        sorted_findings = sorted(self.findings, key=lambda x: (
            x.get('severity') or Severity.INFO,
            -x.get('mtime', 0)
        ), reverse=True)
        
        high_findings = [f for f in sorted_findings if (f.get('severity') or Severity.INFO) >= Severity.HIGH][:10]
        med_findings = [f for f in sorted_findings if (f.get('severity') or Severity.INFO) == Severity.MEDIUM][:20]
        
        report.append(f"\n{'─' * 70}")
        report.append(f"【Findings 摘要】 (已過濾白名單)")
        report.append(f"{'─' * 70}")
        report.append(f"  高風險:       {len(high_findings)} 個")
        report.append(f"  中風險:       {len(med_findings)} 個")
        
        report.append(f"\n{'─' * 70}")
        report.append("【高風險 Findings (Top 10)】")
        report.append(f"{'─' * 70}")
        
        if high_findings:
            for i, f in enumerate(high_findings, 1):
                report.append(f"  {i:2}. {f['path']}")
                rule_id = f.get('rule_id', 'N/A')
                confidence = f.get('confidence', 'N/A')
                method = f.get('method', 'N/A')
                report.append(f"      rule_id={rule_id}, confidence={confidence}, method={method}")
                reasons = f.get('reasons', [])
                for r in reasons[:3]:
                    report.append(f"      + {r}")
                if f.get('decoded'):
                    report.append(f"      解碼內容: {f['decoded'][:60]}...")
                elif f.get('content'):
                    report.append(f"      內容: {f['content'][:60]}...")
                meta = f.get('metadata', {})
                if meta:
                    inode_val = int(meta.get('inode', 0)) if meta.get('inode') else 0
                    report.append(f"      inode={inode_val}, size={meta.get('size', 0)}")
        else:
            report.append("  未發現高風險項目")
        
        if med_findings:
            report.append(f"\n{'─' * 70}")
            report.append("【中風險 Findings (Top 20)】")
            report.append(f"{'─' * 70}")
            for i, f in enumerate(med_findings, 1):
                report.append(f"  {i:2}. {f['path']}")
                rule_id = f.get('rule_id', 'N/A')
                confidence = f.get('confidence', 'N/A')
                method = f.get('method', 'N/A')
                report.append(f"      rule_id={rule_id}, confidence={confidence}, method={method}")
                reasons = f.get('reasons', [])
                for r in reasons[:2]:
                    report.append(f"      + {r}")
        
        report.append(f"\n{'─' * 70}")
        report.append("【時間線 - 最近修改的檔案 (前20)】")
        report.append(f"{'─' * 70}")
        
        recent_files = [f for f in self.timeline if not f.get('is_dir')][:20]
        for i, f in enumerate(recent_files, 1):
            mtime = self.format_time(f.get('mtime', 0))
            report.append(f"  {i:2}. {mtime}  {self.format_size(f['size']):>10}  {f['path']}")
        
        oldest_files = sorted(
            [f for f in self.timeline if not f.get('is_dir') and f.get('mtime', 0) > 0],
            key=lambda x: x.get('mtime', 0)
        )[:20]
        
        report.append(f"\n{'─' * 70}")
        report.append("【時間線 - 最早修改的檔案 (前20)】")
        report.append(f"{'─' * 70}")
        
        for i, f in enumerate(oldest_files, 1):
            mtime = self.format_time(f.get('mtime', 0))
            inode = f.get('inode', '')
            report.append(f"  {i:2}. {mtime}  {self.format_size(f['size']):>10}  inode={inode}  {f['path']}")
        
        outliers = self.find_time_outliers()
        
        if outliers:
            analyzed_outliers = self.analyze_time_outliers_content(outliers[:50])
            
            report.append(f"\n{'─' * 70}")
            report.append("【Timeline Outliers (時間異常分數)】")
            report.append(f"{'─' * 70}")
            report.append(f"  中位數時間: {self.format_time(outliers[0]['median_ts']) if outliers else 'N/A'}")
            report.append(f"  異常檔案數: {len(outliers)} 個 (比中位數早超過 30 天)")
            report.append("")
            
            for i, f in enumerate(analyzed_outliers[:20], 1):
                mtime = self.format_time(f.get('mtime', 0))
                days_diff = int(f.get('time_delta', 0) / 86400)
                report.append(f"  {i:2}. {f['path']}")
                report.append(f"      inode={f.get('inode')}, size={f['size']}, mtime={mtime}")
                report.append(f"      早於中位數: {days_diff} 天")
                
                if f.get('flag_found'):
                    report.append(f"      [FLAG FOUND!] {f['flag_found']}")
                
                if f.get('has_base64'):
                    report.append(f"      base64候選: {f.get('base64_candidates_count')} 個")
                
                if f.get('decoded'):
                    report.append(f"      解碼內容: {f['decoded'][:80]}")
        
        oldest_suspicious = self.find_oldest_suspicious_small_files()
        recent_suspicious = self.find_recent_suspicious_small_files()
        
        scored_oldest = []
        for f in oldest_suspicious:
            f['score'] = self.score_oldest_suspicious(f)
            scored_oldest.append(f)
        scored_oldest = sorted(scored_oldest, key=lambda x: x.get('score', 0), reverse=True)[:10]
        
        scored_recent = []
        for f in recent_suspicious:
            f['score'] = self.score_newest_suspicious(f)
            scored_recent.append(f)
        scored_recent = sorted(scored_recent, key=lambda x: x.get('score', 0), reverse=True)[:10]
        
        decoded_payloads = self.find_readable_decoded_payloads()
        
        if scored_oldest or scored_recent or decoded_payloads:
            report.append(f"\n{'─' * 70}")
            report.append("【高價值線索 TOP 5】")
            report.append(f"{'─' * 70}")
            
            if decoded_payloads:
                report.append(f"\n  [Readable Decoded Payloads - FLAG/LIKE]")
                for i, f in enumerate(decoded_payloads[:5], 1):
                    report.append(f"    {i:2}. {f['path']}")
                    report.append(f"        size={f['size']}, inode={f.get('inode')}")
                    report.append(f"        reason: {f.get('reason', 'decoded')}")
                    report.append(f"        decoded: {f['decoded'][:60]}")
            
            if scored_oldest:
                report.append(f"\n  [Top Oldest Suspicious Small Files]")
                for i, f in enumerate(scored_oldest[:5], 1):
                    mtime = self.format_time(f.get('mtime', 0))
                    score = f.get('score', 0)
                    report.append(f"    {i:2}. {f['path']} (score={score:.1f})")
                    report.append(f"        size={f['size']}, mtime={mtime}")
                    if f.get('decoded'):
                        report.append(f"        decoded: {f['decoded'][:60]}")
            
            if scored_recent:
                report.append(f"\n  [Top Newest Suspicious Small Files]")
                for i, f in enumerate(scored_recent[:5], 1):
                    mtime = self.format_time(f.get('mtime', 0))
                    score = f.get('score', 0)
                    report.append(f"    {i:2}. {f['path']} (score={score:.1f})")
                    report.append(f"        size={f['size']}, mtime={mtime}")
                    if f.get('decoded'):
                        report.append(f"        decoded: {f['decoded'][:60]}")
        
        if oldest_suspicious or recent_suspicious:
            report.append(f"\n{'─' * 70}")
            report.append("【雙候選區 - 可疑小檔案】")
            report.append(f"{'─' * 70}")
            
            if oldest_suspicious:
                report.append(f"\n  [Oldest suspicious small files]")
                report.append(f"  找到 {len(oldest_suspicious)} 個")
                for i, f in enumerate(oldest_suspicious[:10], 1):
                    mtime = self.format_time(f.get('mtime', 0))
                    report.append(f"    {i:2}. {f['path']}")
                    report.append(f"        size={f['size']}, mtime={mtime}")
                    reasons = f.get('reasons', [])
                    for r in reasons[:2]:
                        report.append(f"        + {r}")
                    if f.get('decoded'):
                        report.append(f"        解碼: {f['decoded'][:60]}")
                    elif f.get('content'):
                        report.append(f"        內容: {f['content'][:60]}")
            
            if recent_suspicious:
                report.append(f"\n  [Newest suspicious small files]")
                report.append(f"  找到 {len(recent_suspicious)} 個")
                for i, f in enumerate(recent_suspicious[:10], 1):
                    mtime = self.format_time(f.get('mtime', 0))
                    report.append(f"    {i:2}. {f['path']}")
                    report.append(f"        size={f['size']}, mtime={mtime}")
                    reasons = f.get('reasons', [])
                    for r in reasons[:2]:
                        report.append(f"        + {r}")
                    if f.get('decoded'):
                        report.append(f"        解碼: {f['decoded'][:60]}")
                    elif f.get('content'):
                        report.append(f"        內容: {f['content'][:60]}")
        
        report.append(f"\n{'─' * 70}")
        report.append("【檔案類型統計 (前10)】")
        report.append(f"{'─' * 70}")
        
        sorted_types = sorted(self.file_stats.items(), 
                            key=lambda x: x[1]['size'], 
                            reverse=True)[:10]
        
        for ext, stats in sorted_types:
            pct = (stats['size'] / self.total_size * 100) if self.total_size > 0 else 0
            report.append(f"  {ext:15} {stats['count']:5} 檔案  "
                         f"{self.format_size(stats['size']):>10} ({pct:5.1f}%)")
        
        report.append(f"\n{'─' * 70}")
        report.append("【最大檔案 (前20)】")
        report.append(f"{'─' * 70}")
        
        sorted_by_size = sorted([f for f in self.files if not f.get('is_dir')], 
                              key=lambda x: x['size'], 
                              reverse=True)[:20]
        
        for i, f in enumerate(sorted_by_size, 1):
            report.append(f"  {i:2}. {self.format_size(f['size']):>10}  {f['path']}")
        
        report.append("\n" + "=" * 70)
        
        report_text = '\n'.join(report)
        
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"報告已儲存至: {output}")
        
        return report_text

def main():
    parser = argparse.ArgumentParser(
        description='CTF 磁碟鑑識分析工具 v4.0-rc1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
範例:
  %(prog)s partition4.img --all              # 完整分析
  %(prog)s . --report                        # 報告輸出
  %(prog)s partition4.img --export-csv       # 匯出時間線
        '''
    )
    
    parser.add_argument('path', nargs='?', default='.', help='分析路徑或映像檔')
    parser.add_argument('--verbose', '-v', action='store_true', help='詳細輸出')
    parser.add_argument('--report', '-r', action='store_true', help='產生報告')
    parser.add_argument('--output', '-o', default='ctf_report.txt', help='報告輸出')
    parser.add_argument('--export-csv', action='store_true', help='匯出 CSV')
    parser.add_argument('--export-timeline', action='store_true', help='匯出 timeline JSON')
    parser.add_argument('--export-json', '--export-all', action='store_true', help='匯出完整 JSON (summary+findings+timeline)')
    parser.add_argument('--export-findings', action='store_true', help='匯出 findings JSON')
    parser.add_argument('--export-summary', action='store_true', help='匯出 summary JSON')
    parser.add_argument('--export-payloads', action='store_true', help='匯出 decoded payloads JSON')
    parser.add_argument('--export-artifacts', action='store_true', help='匯出 artifacts 目錄')
    parser.add_argument('--all', '-a', action='store_true', help='執行所有分析')
    parser.add_argument('--max-size', type=int, default=5*1024*1024, help='最大分析檔案大小')
    parser.add_argument('--timeline-limit', type=int, default=None, help='timeline 輸出限制 (預設全量)')
    parser.add_argument('--deep', '-d', action='store_true', help='深度分析可疑路徑')
    parser.add_argument('--time-window', '-t', type=int, default=120, help='時間關聯窗口(秒)')
    parser.add_argument('--decode-base64', action='store_true', help='自動解碼 base64 內容')
    parser.add_argument('--time-correlations', action='store_true', help='分析時間關聯性')
    parser.add_argument('--partition', '-p', type=int, default=None, help='選擇分割區索引 (從 0 開始)')
    parser.add_argument('--list-partitions', '-l', action='store_true', help='列出所有分割區')
    
    args = parser.parse_args()
    
    analyzer = DiskAnalyzer(args.path, verbose=args.verbose)
    
    image_type = analyzer.detect_image_type()
    if image_type:
        print(f"偵測到映像檔類型: {image_type}")
    
    if analyzer.is_image and image_type and image_type.startswith('ext'):
        partitions = analyzer.detect_partitions()
        if partitions:
            print(f"偵測到 {len(partitions)} 個分割區:")
            for i, p in enumerate(partitions):
                print(f"  [{i}] {p['type']}: offset={p['offset_bytes']}, size={p['size_sectors']} sectors, {p['description']}")
            
            if args.list_partitions:
                return
            
            if args.partition is not None:
                selected = analyzer.select_partition(args.partition)
                if selected:
                    print(f"已選擇分割區 {args.partition}")
            elif len(partitions) > 1:
                linux_parts = [i for i, p in enumerate(partitions) if p['type'] == 'linux']
                if linux_parts:
                    analyzer.select_partition(linux_parts[0])
                    print(f"自動選擇 Linux 分割區 {linux_parts[0]}")
    
    analyzer.scan_directory()
    
    if args.all or args.deep:
        analyzer.deep_analyze_suspicious_files()
    
    if args.decode_base64:
        count = analyzer.decode_findings_base64()
        print(f"已解碼 {count} 個 base64 內容")
    
    if args.time_correlations:
        correlations = analyzer.analyze_time_correlations(time_window=args.time_window)
        if correlations:
            print(f"\n發現 {len(correlations)} 個時間關聯群組")
            for c in correlations[:5]:
                print(f"  {datetime.fromtimestamp(c['time'])}: {c['count']} 個檔案")
    
    if args.all:
        analyzer.analyze_files(max_size=args.max_size)
        analyzer.analyze_suspicious_paths()
    
    analyzer.build_timeline()
    
    analysis_options = {
        'deep': args.all or args.deep,
        'content': args.all,
        'time_correlations': args.time_correlations,
        'decode_base64': args.decode_base64,
        'max_size': args.max_size,
        'timeline_limit': args.timeline_limit,
    }
    
    if args.export_csv:
        analyzer.export_timeline_csv()
    
    if args.export_timeline:
        analyzer.export_timeline_json(limit=args.timeline_limit)
    
    if args.export_json:
        analyzer.export_all_json(timeline_limit=args.timeline_limit or DEFAULT_FULL_EXPORT_TIMELINE_LIMIT, analysis_options=analysis_options)
    
    if args.export_findings:
        analyzer.export_findings_json()
    
    if args.export_summary:
        analyzer.export_summary_json(analysis_options=analysis_options)
    
    if args.export_payloads:
        analyzer.export_payloads_json()
    
    if args.export_artifacts:
        analyzer.export_artifacts()
    
    if args.all or args.report:
        output_file = args.output if args.report else None
        print(analyzer.generate_report(output_file))

if __name__ == '__main__':
    main()
