#!/usr/bin/env python3
import re
import os
import sys
import psutil
import argparse
import subprocess
from datetime import datetime

# 保持原有的特征库不变
STRONG_PATTERNS = {
    "Godzilla": [
        (r"getBasicsInfo", "基础信息获取方法getBasicsInfo(关键特征!)"),
        (r"ValueInstantiators\d{13}", "时间戳类名(关键特征!)"),
        (r"srcFileName|destFileName", "文件操作特征srcFileName|destFileName(关键特征!)"),
        (r"org\.apache\.coyote\.deser", "非常规包路径"),
        (r"_\$jspService\(", "动态JSP服务方法"),
        (r"pass=[A-Za-z0-9]{4,8}&", "哥斯拉密钥协商特征"),
        (r"Cookie:.*?;", "哥斯拉Cookie特征"),
        (r"Runtime\..*?getRuntime", "动态Runtime调用")
    ],
    "Behinder": [
        (r"e45e329feb5d925b", "默认AES密钥(关键特征!)"),
        (r"/agentmemshell|/rebeyond|/memshell|/bypassServlet", "内存马路径特征/agentmemshell|/memshell|/shell/rebeyond"),
        (r"basicInfo|currentPath|driveList", "基本信息获取特征basicInfo|currentPath|driveList"),
        (r"rebeyond", "rebeyond默认密码特征"),
        (r"application/octet-stream.*?Content-Length: 16", "冰蝎4流量特征")
    ],
    "Dynamic": [
        (r"filterChain\.doFilter", "Filter链劫持"),
        (r"StandardContext\..*children", "动态Servlet注册"),
        (r"\.jsp\$_", "JSP编译特征"),
        (r"cafebaby|CAFEBABY|yv66vg|gozilla|behinder", "内存马字节码特征")
    ],
    "Agent": [
        (r"javax/servlet/http/HttpServlet#service", "Servlet方法注入"),
        (r"org/apache/catalina/core/ApplicationFilterChain#doFilter", "Filter链注入"),
        (r"sun/misc/Unsafe#defineAnonymousClass", "匿名类动态加载")
    ],
    "Spring": [
        (r"RequestMappingHandlerAdapter.*?invokeHandlerMethod", "处理器方法注入")
    ]
}

def get_pid_by_port(port):
    """通过端口号获取PID"""
    try:
        if sys.platform == 'win32':
            cmd = f"netstat -ano | findstr :{port}"
            output = subprocess.check_output(cmd, shell=True).decode()
            return int(output.strip().split()[-1])
        else:
            cmd = f"lsof -i :{port} | awk 'NR==2{{print $2}}'"
            pid = subprocess.check_output(cmd, shell=True).decode().strip()
            return int(pid) if pid else None
    except Exception as e:
        print(f"[!] 获取端口{port}的PID失败: {str(e)}")
        return None

def dump_heap(pid):
    """生成堆转储文件"""
    dump_file = f"heapdump_{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.hprof"
    try:
        cmd = f"jmap -dump:live,format=b,file={dump_file} {pid}"
        subprocess.run(cmd, shell=True, check=True)
        return dump_file if os.path.exists(dump_file) else None
    except Exception as e:
        print(f"[!] 生成堆转储文件失败: {str(e)}")
        return None

def detect_memory_malware(file_path):
    """内存马检测主函数"""
    log_file = f"memshell_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    with open(log_file, 'w') as f:
        f.write(f"=== 内存马深度检测报告 {datetime.now()} ===\n")
        f.write(f"目标文件: {file_path}\n")
        f.write(f"系统内存使用: {psutil.virtual_memory().percent}%\n\n")
        
        # 执行各类型检测
        detection_results = {}
        for category in STRONG_PATTERNS:
            detection_results[category] = detect_category(file_path, f, category)
        
        # 输出详细检测结果
        f.write("\n[详细检测结果]\n")
        for category, results in detection_results.items():
            f.write(f"{category}检测:\n")
            if results:
                for desc in results:
                    f.write(f"  - 发现特征: {desc}\n")
                    if "默认密码特征" in desc and "rebeyond" in desc:
                        f.write("    [!] 严重警告: 检测到冰蝎默认密码'rebeyond'，系统存在极高风险！\n")
            else:
                f.write("  - 未发现明确特征\n")
        
        f.write("\n[检测建议]\n")
        f.write("1. 使用Arthas检查动态组件: sc *.Filter|grep -E 'shell|memshell'\n")
        f.write("2. 检查StandardContext中的异常children项\n")
        f.write(f"3. 详细报告已保存至: {os.path.abspath(log_file)}\n")

def detect_category(file_path, log_file, category):
    """检测特定类型的内存马特征"""
    found_patterns = set()
    
    with open(file_path, 'rb') as f:
        content = f.read().decode('latin1')
        
        for pattern, desc in STRONG_PATTERNS[category]:
            if re.search(pattern, content) and desc not in found_patterns:
                log_file.write(f"[高危] 检测到{desc}\n")
                found_patterns.add(desc)
    
    if not found_patterns:
        log_file.write("未发现明确特征\n")
    
    return found_patterns

def main():
    parser = argparse.ArgumentParser(description='内存马检测工具')
    parser.add_argument('-p', '--port', type=int, help='指定Tomcat服务端口号')
    parser.add_argument('-f', '--file', help='直接指定堆转储文件路径')
    args = parser.parse_args()

    if args.port:
        print(f"[*] 正在检测端口 {args.port} 的Tomcat服务...")
        pid = get_pid_by_port(args.port)
        if not pid:
            print(f"[!] 未找到监听端口 {args.port} 的进程")
            return
        
        print(f"[+] 找到PID: {pid}, 正在生成堆转储文件...")
        dump_file = dump_heap(pid)
        if not dump_file:
            return
        
        print(f"[+] 堆转储文件已生成: {dump_file}")
        detect_memory_malware(dump_file)
    elif args.file:
        if not os.path.exists(args.file):
            print(f"[!] 文件不存在: {args.file}")
            return
        detect_memory_malware(args.file)
    else:
        print("请指定检测模式:")
        print("  1. 通过端口检测: python script.py -p 8080")
        print("  2. 直接检测堆转储文件: python script.py -f heapdump.hprof")

if __name__ == "__main__":
    main()