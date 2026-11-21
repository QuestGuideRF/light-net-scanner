import io
import os
import re
import sys
import time
import platform
import socket
import logging
import datetime
import ipaddress
import subprocess
import concurrent .futures
import threading
import itertools
from typing import List ,Dict ,Iterable ,Optional
from io import StringIO
from typing import Optional
log_buffer =io .StringIO ()
now =datetime .datetime .now ().replace (microsecond =0 )
def setup_logger (level =logging .INFO ,logfile :Optional [str ]=None ):
    ch =logging .StreamHandler ()
    ch .setFormatter (logging .Formatter ("%(сообщение)с"))
    handlers =[ch ]
    fh =None
    if logfile :
        fh =logging .FileHandler (logfile )
        fh .setFormatter (logging .Formatter ("%(asctime)s [%(имя уровня)s] %(сообщение)s",datefmt ="%Y-%m-%d %H:%M:%S"))
        handlers .append (fh )
    sh =logging .StreamHandler (log_buffer )
    sh .setFormatter (logging .Formatter ("%(asctime)s [%(имя уровня)s] %(сообщение)s",datefmt ="%Y-%m-%d %H:%M:%S"))
    handlers .append (sh )
    logging .basicConfig (level =level ,handlers =handlers )
def ensure_console (title :str ="Сетевой сканер"):
    if sys .platform .startswith ("win"):
        try :
            import ctypes
            kernel32 =ctypes .windll .kernel32
            ATTACH_PARENT_PROCESS =-1
            if not kernel32 .AttachConsole (ATTACH_PARENT_PROCESS ):
                kernel32 .AllocConsole ()
            sys .stdout =open ("CONOUT$","w",buffering =1 ,encoding ="utf-8",errors ="ignore")
            sys .stderr =open ("CONOUT$","w",buffering =1 ,encoding ="utf-8",errors ="ignore")
            sys .stdin =open ("КОНИН$","r",encoding ="utf-8",errors ="ignore")
            try :
                kernel32 .SetConsoleTitleW (str (title ))
            except Exception :
                pass
            try :
                os .system ("цвет 07")
            except Exception :
                pass
        except Exception :
            pass
class Spinner :
    def __init__ (self ,message :str ="Запуск сканирования"):
        self .message =message
        self ._stop_event =threading .Event ()
        self .thread =threading .Thread (target =self ._spin ,daemon =True )
    def _spin (self ):
        for dots in itertools .cycle (["",".","..","...","....","....."]):
            if self ._stop_event .is_set ():
                break
            print (f"\r{self .message }{dots }   ",end ="",flush =True )
            time .sleep (0.5 )
        print ("\r"+" "*(len (self .message )+10 )+"\r",end ="",flush =True )
    def start (self ):
        self .thread .start ()
    def stop (self ):
        self ._stop_event .set ()
        self .thread .join ()
COMMON_PORTS =[21 ,22 ,23 ,67 ,68 ,69 ,80 ,123 ,53 ,161 ,389 ,443 ,445 ,1433 ,3389 ,5900 ]
IS_WINDOWS =platform .system ().lower ().startswith ("win")
if IS_WINDOWS :
    WINDOWS_CREATE_NO_WINDOW =0x08000000
    try :
        STARTUPINFO =subprocess .STARTUPINFO ()
        STARTUPINFO .dwFlags |=subprocess .STARTF_USESHOWWINDOW
        STARTUPINFO .wShowWindow =subprocess .SW_HIDE
    except Exception :
        STARTUPINFO =None
else :
    WINDOWS_CREATE_NO_WINDOW =0
    STARTUPINFO =None
def _subproc_kwargs_hide_window ()->dict :
    if IS_WINDOWS :
        kwargs ={"creationflags":WINDOWS_CREATE_NO_WINDOW }
        if STARTUPINFO is not None :
            kwargs ["startupinfo"]=STARTUPINFO
        return kwargs
    return {}
def _run_check_output (cmd ,shell =False ,**kwargs )->str :
    base_kwargs ={"text":True ,"encoding":"utf-8","errors":"ignore","shell":shell }
    base_kwargs .update (_subproc_kwargs_hide_window ())
    base_kwargs .update (kwargs )
    return subprocess .check_output (cmd ,**base_kwargs )
def _run_subprocess_run (cmd ,shell =False ,**kwargs )->subprocess .CompletedProcess :
    base_kwargs ={"stdout":subprocess .DEVNULL ,"stderr":subprocess .DEVNULL ,"shell":shell }
    base_kwargs .update (_subproc_kwargs_hide_window ())
    base_kwargs .update (kwargs )
    return subprocess .run (cmd ,**base_kwargs )
def _local_ip ()->Optional [str ]:
    try :
        s =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
        s .settimeout (1.0 )
        s .connect (("8.8.8.8",80 ))
        ip =s .getsockname ()[0 ]
        s .close ()
        return ip
    except Exception :
        return None
def guess_subnet (ip :Optional [str ],mask_bits :int =24 )->ipaddress .IPv4Network :
    if not ip :
        return ipaddress .ip_network ("0.0.0.0/0")
    return ipaddress .ip_network (f"{ip }/{mask_bits }",strict =False )
def _ping (ip :str ,timeout_ms :int =500 ,rate :int =10 )->bool :
    try :
        if IS_WINDOWS :
            cmd =["ping","-n","1","-w",str (timeout_ms ),ip ]
            proc =_run_subprocess_run (cmd ,shell =False )
        else :
            timeout_s =max (1 ,int ((timeout_ms +999 )//1000 ))
            cmd =["ping","-c","1","-W",str (timeout_s ),ip ]
            proc =_run_subprocess_run (cmd ,shell =False )
        if rate >0 :
            time .sleep (1 /rate )
        return proc .returncode ==0
    except Exception :
        return False
def _parse_arp_table ()->Dict [str ,str ]:
    ip_to_mac ={}
    try :
        out =_run_check_output (["arp","-a"],shell =False )
        if IS_WINDOWS :
            for line in out .splitlines ():
                m =re .search (r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{14,17})",line )
                if m :
                    ip ,mac =m .group (1 ),m .group (2 ).replace ("–",":").lower ()
                    ip_to_mac [ip ]=mac
        else :
            for line in out .splitlines ():
                m =re .search (r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})",line )
                if m :
                    ip ,mac =m .group (1 ),m .group (2 ).lower ()
                    ip_to_mac [ip ]=mac
    except Exception :
        pass
    return ip_to_mac
def _resolve_hostname (ip :str ,timeout :float =0.5 )->str :
    try :
        with concurrent .futures .ThreadPoolExecutor (max_workers =1 )as ex :
            fut =ex .submit (socket .gethostbyaddr ,ip )
            return fut .result (timeout =timeout )[0 ]
    except Exception :
        pass
    if platform .system ().lower ()=="windows":
        return "N/A"
    def cmd_exists (cmd :str )->bool :
        return subprocess .call (
        f"command -v {cmd } >/dev/null 2>&1",shell =True
        )==0
    if cmd_exists ("nmblookup"):
        try :
            result =subprocess .check_output (
            ["nmblookup","-A",ip ],
            stderr =subprocess .DEVNULL ,
            timeout =timeout ,
            text =True
            )
            for line in result .splitlines ():
                if "<00>"in line and "GROUP"not in line :
                    return line .split ()[0 ]
        except Exception :
            pass
    if cmd_exists ("avahi-resolve-address"):
        try :
            result =subprocess .check_output (
            ["avahi-resolve-address",ip ],
            stderr =subprocess .DEVNULL ,
            timeout =timeout ,
            text =True
            ).strip ()
            if result and " "in result :
                return result .split ()[-1 ]
        except Exception :
            pass
    return "N/A"
def _scan_ports (ip :str ,ports :Iterable [int ],timeout :float =0.5 ,max_workers :int =100 )->List [int ]:
    open_ports =[]
    ports_list =list (ports )
    if not ports_list :
        return []
    def _try_port (port :int )->Optional [int ]:
        try :
            with socket .socket (socket .AF_INET ,socket .SOCK_STREAM )as s :
                s .settimeout (timeout )
                if s .connect_ex ((ip ,port ))==0 :
                    return port
        except Exception :
            pass
        return None
    worker_count =min (max_workers ,len (ports_list ))
    with concurrent .futures .ThreadPoolExecutor (max_workers =worker_count )as ex :
        futures ={ex .submit (_try_port ,p ):p for p in ports_list }
        for fut in concurrent .futures .as_completed (futures ):
            res =fut .result ()
            if res :
                open_ports .append (res )
    return sorted (open_ports )
def discover_hosts (subnet :ipaddress .IPv4Network ,max_workers :int =200 ,ping_timeout_ms :int =400 )->List [str ]:
    ips =[str (ip )for ip in subnet .hosts ()]
    alive =[]
    if not ips :
        return []
    with concurrent .futures .ThreadPoolExecutor (max_workers =min (max_workers ,len (ips )))as ex :
        futures ={ex .submit (_ping ,ip ,ping_timeout_ms ):ip for ip in ips }
        for fut in concurrent .futures .as_completed (futures ):
            ip =futures [fut ]
            try :
                if fut .result ():
                    alive .append (ip )
            except Exception :
                pass
    return sorted (alive ,key =lambda x :socket .inet_aton (x ))
def discover_network (subnet :Optional [ipaddress .IPv4Network ]=None ,
ports :Optional [Iterable [int ]]=None ,
do_port_scan :bool =True ,
fast :bool =True )->List [Dict ]:
    if ports is None :
        ports =COMMON_PORTS
    local_ip =_local_ip ()
    if subnet is None :
        subnet =guess_subnet (local_ip ,24 )
    ping_timeout =300 if fast else 800
    port_timeout =0.4 if fast else 1.2
    alive_ips =discover_hosts (subnet ,ping_timeout_ms =ping_timeout )
    if local_ip in alive_ips :
        alive_ips .remove (local_ip )
    ip_mac =_parse_arp_table ()
    devices =[]
    with concurrent .futures .ThreadPoolExecutor (max_workers =100 )as ex :
        port_futures ={}
        for ip in alive_ips :
            if do_port_scan :
                port_futures [ip ]=ex .submit (_scan_ports ,ip ,ports ,port_timeout ,200 )
        for ip in alive_ips :
            hostname =_resolve_hostname (ip ,timeout =0.5 if fast else 1.5 )
            mac =ip_mac .get (ip )
            open_ports =[]
            if do_port_scan and ip in port_futures :
                try :
                    open_ports =port_futures [ip ].result (timeout =10 )
                except Exception :
                    open_ports =[]
            devices .append ({
            "ip":ip ,
            "hostname":hostname ,
            "mac":mac ,
            "alive":True ,
            "open_ports":open_ports
            })
    return devices
def _highlight_risky_ports (ports :Iterable [int ])->List [str ]:
    mapping ={}
    return [f"{p }({mapping .get (p ,'')})"if p in mapping else str (p )for p in ports ]
def test_print (subnet :Optional [ipaddress .IPv4Network ]=None ,
do_port_scan :bool =True ,
fast :bool =True ,
ports :Optional [Iterable [int ]]=None ):
    if subnet is None :
        local =_local_ip ()
        subnet =guess_subnet (local ,24 )
    devices =discover_network (subnet =subnet ,do_port_scan =do_port_scan ,fast =fast ,ports =ports )
    headers =["IP","Hostname","MAC","Alive","Открытые порты"]
    col_widths =[15 ,20 ,20 ,10 ,40 ]
    def _trim (s :str ,w :int )->str :
        return (s [:w -3 ]+"...")if len (s )>w else s
    header_line ="  ".join (h .center (w )for h ,w in zip (headers ,col_widths ))
    sep_line ="–"*len (header_line )
    logging .info (f"\n\nScanned subnet: {subnet } — found {len (devices )} devices")
    logging .info (sep_line )
    logging .info (header_line )
    logging .info (sep_line )
    for d in devices :
        ip =_trim (d ["ip"],col_widths [0 ])
        host =_trim (d ["hostname"]or "N/A",col_widths [1 ])
        mac =_trim (d ["mac"]or "N/A",col_widths [2 ])
        alive =str (d ["alive"])
        if d ["open_ports"]:
            ports_str =", ".join (_highlight_risky_ports (d ["open_ports"]))
        else :
            ports_str ="N/A"
        ports_str =_trim (ports_str ,col_widths [4 ])
        logging .info (f"{ip .ljust (col_widths [0 ])}  {host .center (col_widths [1 ])}  {mac .center (col_widths [2 ])}  {alive .center (col_widths [3 ])}  {ports_str .center (col_widths [4 ])}")
    logging .info (sep_line )
if __name__ =="__main__":
    ensure_console ("Легкий сетевой сканер")
    log_level =logging .DEBUG if "--debug"in sys .argv else logging .INFO
    log_file =None
    if "--log"in sys .argv :
        try :
            idx =sys .argv .index ("--log")
            log_file =sys .argv [idx +1 ]
        except Exception :
            log_file ="scan.log"
    setup_logger (level =log_level ,logfile =log_file )
    logging .info (f"{now }")
    logging .info ("Обнаружение локального IP...")
    local =_local_ip ()
    logging .info (f"Local IP: {local }")
    subnet =guess_subnet (local ,24 )
    logging .info (f"Guessed subnet: {subnet }")
    target_ips =None
    MAX_RANGE_SIZE =512
    def _ip_range_from_full_ips (start_ip :str ,end_ip :str )->List [str ]:
        a =ipaddress .IPv4Address (start_ip )
        b =ipaddress .IPv4Address (end_ip )
        if int (b )<int (a ):
            raise ValueError ("Конечный IP меньше начального IP")
        size =int (b )-int (a )+1
        if size >MAX_RANGE_SIZE :
            raise ValueError (f"Range too large ({size } IPs); max is {MAX_RANGE_SIZE }")
        return [str (ipaddress .IPv4Address (int (a )+i ))for i in range (size )]
    def _ip_range_from_last_octets (base_ip_prefix :str ,start_oct :int ,end_oct :int )->List [str ]:
        if start_oct <1 or end_oct >254 or start_oct >end_oct :
            raise ValueError ("Неверный диапазон последнего октета; должно быть 1..254 и начало<=конец")
        size =end_oct -start_oct +1
        if size >MAX_RANGE_SIZE :
            raise ValueError (f"Range too large ({size } IPs); max is {MAX_RANGE_SIZE }")
        return [f"{base_ip_prefix }.{i }"for i in range (start_oct ,end_oct +1 )]
    while True :
        choice =input ("\nЧтобы начать сканирование сети, введите «Y» (или «N», чтобы пропустить): ").strip ().upper ()
        if choice =="Y":
            spinner =Spinner ("Запуск сканирования")
            spinner .start ()
            start =time .time ()
            try :
                devices =[]
                test_print (subnet =subnet ,do_port_scan =True ,fast =True )
            except KeyboardInterrupt :
                logging .warning ("Сканирование отменено пользователем (KeyboardInterrupt).")
                print ("\nСканирование отменено пользователем.")
            finally :
                spinner .stop ()
                elapsed =time .time ()-start
                logging .info (f"Scan finished in {elapsed :.1f}s")
            export =input ("\nЭкспортировать журналы в текстовый файл? (Y для экспорта, Enter для пропуска): ").strip ().lower ()
            if export =="y":
                export_path ="scan_log_export.txt"
                with open (export_path ,"w",encoding ="utf-8")as f :
                    f .write (log_buffer .getvalue ())
                print (f"Logs exported → {export_path }")
            input ("\nСканирование завершено! Нажмите Enter, чтобы выйти...")
            break
        elif choice =="N":
            input ("\nСканирование пропущено. Нажмите Enter, чтобы выйти...")
            break
        else :
            print ("Неверный ввод!")