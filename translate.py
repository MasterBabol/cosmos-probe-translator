#!/usr/bin/python
# Author: Kibin Park
# Email: babol@live.co.kr
# License: MIT
import sys
import re
import io
import copy

class CursoredData:
    def __init__(self, bytesio_data):
        self.rdata = bytesio_data
        self.rdata.seek(0)
    
    def get(self, type_name):
        if type_name == 'uint64_t':
            type_size = 8
        elif type_name == 'uint32_t':
            type_size = 4
        elif type_name == 'uint16_t':
            type_size = 2
        elif type_name == 'uint8_t':
            type_size = 1
        else:
            raise AttributeError()
        return int.from_bytes(self.rdata.read(type_size), "little")

def cursored_data_to_log(payload_types, cdata):
    log = {}
    log['type'] = cdata.get('uint32_t')
    log['tier'] = cdata.get('uint32_t')
    log['status'] = cdata.get('uint32_t')
    log['payload'] = {}
    
    payload_type = payload_types[log['type']]
    for tup in payload_type:
        if tup[2] is not None and int(tup[2]) > 1:
            log['payload'][tup[1]] = []
            for it in range(0, int(tup[2])):
                log['payload'][tup[1]].append(cdata.get(tup[0]))
        else:
            log['payload'][tup[1]] = cdata.get(tup[0])
    
    return log
    
def transform_log_to_readable(log_format, log):
    log = copy.deepcopy(log)
    log['type'] = log_format['types'][log['type']]
    log['tier'] = log_format['tiers'][log['tier']]
    log['status'] = log_format['valid'][log['status']]
    for k in log['payload']:
        if k == 'subject':
            log['payload'][k] = log_format['psubject'][log['payload'][k]]
        elif k == 'action':
            log['payload'][k] = log_format['paction'][log['payload'][k]]
        elif k == 'fromObject':
            log['payload'][k] = log_format['pobject'][log['payload'][k]]
        elif k == 'toObject':
            log['payload'][k] = log_format['pobject'][log['payload'][k]]
        
    return log

def print_dict(log, level=0):
    for k, v in log.items():
        if isinstance(v, dict):
            print_dict(v, level+1)
        else:
            print(' ' * level * 2 + k + ': ' + str(v))

def print_log(log):
    print_dict(log)
    print()
    
def save_dict(file, log, level=0):
    for k, v in log.items():
        if isinstance(v, dict):
            save_dict(file, v, level+1)
        else:
            file.write(' ' * level * 2 + k + ': ' + str(v) + '\n')

def save_log(file, log):
    save_dict(file, log)
    file.write('\n')

def rawlog_to_bytesio(rdata):
    re_col_pat = '\s*\w+\s*,?'
    re_trim_pat = '\s*(\w+)\s*,?'
    listed_rdata = re.findall(re_col_pat, rdata)
    bindata = io.BytesIO()
    
    for uint32_assumed_rdata in listed_rdata:
        m = re.search(re_trim_pat, uint32_assumed_rdata)
        trimmed_rdata = m.group(1)
        udata = int(trimmed_rdata, 16)
        bindata.write(udata.to_bytes(4, "little"))

    return bindata

def rewrite_number_types(format_rawcontent):
    format_rawcontent = format_rawcontent.replace('unsigned long long', 'uint64_t')
    format_rawcontent = format_rawcontent.replace('unsigned long', 'uint32_t')
    format_rawcontent = format_rawcontent.replace('unsigned int', 'uint32_t')
    format_rawcontent = format_rawcontent.replace('unsigned short', 'uint16_t')
    format_rawcontent = format_rawcontent.replace('unsigned char', 'uint8_t')
    format_rawcontent = format_rawcontent.replace('XTime', 'uint64_t')
    return format_rawcontent

def parse_enums_to_list(format_rawcontent, target_name):
    ret_list = []
    re_mat_pat = '\s*typedef\s+enum\s+_' + target_name + '\s*{((?:\s*[^}]+\s*,?)+)}\s*.*\s*;'
    re_trim_pat = '\s*' + target_name + '_(\w+)\s*,?\s*'
    
    m = re.search(re_mat_pat, format_rawcontent)
    raw_members_str = m.group(1)
    raw_members = raw_members_str.splitlines()
    
    for rmem in raw_members:
        m = re.search(re_trim_pat, rmem)
        if m is not None:
            ret_list.append(m.group(1))
    
    return ret_list

def parse_struct_to_list_of_tuple(format_rawcontent, target_name):
    ret_list = []
    re_mat_pat = '\s*typedef\s+struct\s+_' + target_name + '\s*{((?:\s*[^}]+\s*,?)+)}\s*.*\s*;'
    re_mem_pat = '\s*((?:uint\d+_t)+)\s+(\w+)\s*(?:\[(\d+)\])?\s*;\s*'
    
    m = re.search(re_mat_pat, format_rawcontent)
    raw_members_str = m.group(1)
    raw_members = raw_members_str.splitlines()
    
    for rmem in raw_members:
        m = re.search(re_mem_pat, rmem)
        if m is not None:
            new_mem = (m.group(1), m.group(2), m.group(3))
            ret_list.append(new_mem)
    
    return ret_list

def parse_payload_types(format_rawcontent, log_types):
    payload_types = []
    
    for ltype in log_types:
        new_payload_type = parse_struct_to_list_of_tuple(format_rawcontent, "PAYLOAD_FOR_LOG_TYPE_" + ltype)
        payload_types.append(new_payload_type)
    
    return payload_types
    

def translate(log_filename, format_filename):
    with open(format_filename) as f:
        format_rawcontent = f.read()
    format_rawcontent = rewrite_number_types(format_rawcontent)

    log_types = parse_enums_to_list(format_rawcontent, "LOG_TYPE")
    log_tiers = parse_enums_to_list(format_rawcontent, "LOG_TIER")
    log_valid = parse_enums_to_list(format_rawcontent, "LOG_VALID")
    
    log_psubject = parse_enums_to_list(format_rawcontent, "PAYLOAD_SUBJECT")
    log_paction = parse_enums_to_list(format_rawcontent, "PAYLOAD_ACTION")
    log_pobject = parse_enums_to_list(format_rawcontent, "PAYLOAD_OBJECT")
    
    payload_types = parse_payload_types(format_rawcontent, log_types)
    
    log_format = {}
    log_format['types'] = log_types
    log_format['tiers'] = log_tiers
    log_format['valid'] = log_valid
    log_format['psubject'] = log_psubject
    log_format['paction'] = log_paction
    log_format['pobject'] = log_pobject
    log_format['ptypes'] = payload_types
    
    translated_logs = []
    
    with open(log_filename) as f:
        while True:
            rdata = f.readline()
            if not rdata: break
            if rdata.isspace(): continue
            
            rdata_bin = rawlog_to_bytesio(rdata)
            ld_raw = CursoredData(rdata_bin)
            log = cursored_data_to_log(payload_types, ld_raw)
            log = transform_log_to_readable(log_format, log)
            translated_logs.append(log)
    
    return log_format, translated_logs

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print('Usage: python translate.py [log file name: optional/default->log.txt] [format file name: optional/default->log_format.h]')
    else:
        log_filename = sys.argv[1] if len(sys.argv) > 1  else "log.txt"
        format_filename = sys.argv[2] if len(sys.argv) > 2 else "log_format.h"
    
        formats, logs = translate(log_filename, format_filename)
        
        files = {}
        for ltype in formats['types']:
            files[ltype] = open('log_of_' + ltype + '.txt', 'w')
        
        for l in logs:
            print_log(l)
            save_log(files[l['type']], l)
        
