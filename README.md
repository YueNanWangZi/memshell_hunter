# memshell_hunter-快速发现内存马

##  这是啥？
###  精准识别memshell
五大类内存马特征检测：  
- 哥斯拉的密钥协商特征  
- 冰蝎的默认AES密钥  
- Filter/Servlet注入特征  
- Java Agent注入特征  
- Spring内存马特征  
###  分析方式
​​- 端口检测​​：自动抓取Java进程生成堆转储  
​​- 直接分析​​：支持已有堆转储文件分析    

### 工具特点
- ​​更方便：指定目标端口，就能得知那个端口是否存在内存马  
​​- 更轻量​​：就一个Python脚本，不用装一堆依赖  
​​- 更聚焦​​：专门针对Java内存马优化  
​​- 更直观​​：直接告诉你发现什么特征，不用自己分析字节码  

###  为啥写这个？
时间就是金钱，我想做一个秒出检测结果的脚本  

##  怎么用？
### 安装依赖
pip install psutil  
### 检测运行中的Java服务
python memshell_hunter.py -p 8080  # 替换成你的Tomcat端口  
### 或者直接分析堆转储文件
python memshell_hunter.py -f heapdump.hprof
### 查看报告
工具会在当前目录生成memshell_scan_时间戳.log，里面详细记录了检测结果

##  技术原理
###  特征匹配
基于正则表达式匹配内存马特征

###  堆转储分析
通过jmap生成堆转储，直接分析内存中的字节码

## ⚠️ 注意事项
需要JDK环境（要用jmap）  
分析大堆转储文件时可能需要一丢丢时间  
目前主要支持windows平台，Linux暂未测试  

## 🔗 项目地址
https://github.com/YueNanWangZi/memshell_hunter

💡 ​自用脚本，出炉不久，还在持续完善中，欢迎提issue！

