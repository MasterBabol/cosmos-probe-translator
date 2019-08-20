#!/usr/bin/python
# Author: Kibin Park
# Email: babol@live.co.kr
# License: MIT
import sys
import re
import io
import copy
import os
import sqlite3 as sl3
from itertools import chain
from datetime import datetime

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
        if 'subject' in k:
            log['payload'][k] = log_format['psubject'][log['payload'][k]]
        elif 'action' in k:
            log['payload'][k] = log_format['paction'][log['payload'][k]]
        elif 'fromObject' in k:
            log['payload'][k] = log_format['pobject'][log['payload'][k]]
        elif 'toObject' in k:
            log['payload'][k] = log_format['pobject'][log['payload'][k]]
        elif 'chNo' == k or 'wayNo' == k:
            log['payload'][k] = log['payload'][k] if int(log['payload'][k]) != 4294967295 else 'not specified'
        
    return log

def print_dict(log, level=0, additional_line_per_item=False):
    for k, v in log.items():
        if isinstance(v, dict):
            print_dict(v, level+1)
        else:
            print(' ' * level * 2 + k + ': ' + str(v))
            if additional_line_per_item is True:
                print()

def print_log(log):
    print_dict(log)
    print()

def flatten_dict(dict_data, remove_meta = False):
    cur_map = {}
    for k, v in dict_data.items():
        if remove_meta == True:
            if k == 'type' or k == 'tier' or k == 'status':
                continue
        if isinstance(v, dict):
            cur_map.update(flatten_dict(v))
        elif isinstance(v, list):
            cur = 0
            for lv in v:
                cur_map[k + '[' + str(cur) + ']'] = lv
                cur += 1
        else:
            cur_map[k] = v
    return cur_map
    
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

def parse_struct_to_list_of_tuple(format_rawcontent, target_name, substruct_types):
    _, ret_list = parse_struct_to_name_and_list_of_tuple(format_rawcontent, target_name, substruct_types)
    return ret_list

def parse_struct_to_name_and_list_of_tuple(format_rawcontent, target_prefix, substruct_types):
    ret_list = []
    re_mat_pat = '\s*typedef\s+struct\s+_' + target_prefix + '(w*)\s*{((?:\s*[^}]+\s*,?)+)}\s*.*\s*;'
    re_mem_pat = '\s*((?:[\w\s^;])+)\s+(\w+)\s*(?:\[(\d+)\])?\s*;\s*(?://.*|/\*.*\*/)*'
    
    m = re.search(re_mat_pat, format_rawcontent)
    target_name = m.group(1)
    raw_members_str = m.group(2)
    raw_members = raw_members_str.splitlines()
    
    for rmem in raw_members:
        m = re.search(re_mem_pat, rmem)
        if m is not None:
            tname = m.group(1)
            vname = m.group(2)
            if tname in substruct_types:
                tlist = substruct_types[tname]
                its = int(m.group(3)) if m.group(3) is not None else 1
                for i in range(0, its):
                    itname = ('[' + str(i) + ']') if its > 1 else ''
                    for sstype in tlist:
                        new_mem = (sstype[0], vname + itname + '.' + sstype[1], sstype[2])
                        ret_list.append(new_mem)
            else:
                new_mem = (m.group(1), m.group(2), m.group(3)) # type_name, var_name, counts
                ret_list.append(new_mem)
    
    return target_name, ret_list

def parse_payload_types_to_list(format_rawcontent, log_types, substruct_types):
    payload_types = []
    
    for ltype in log_types:
        new_payload_type = parse_struct_to_list_of_tuple(format_rawcontent, "PAYLOAD_FOR_LOG_TYPE_" + ltype, substruct_types)
        payload_types.append(new_payload_type)
    
    return payload_types

def parse_substruct_types_to_dict(format_rawcontent):
    substruct_types = {}
    
    re_mat_pat = '\s*typedef\s+struct\s+_STRUCT_(\w*)\s*{((?:\s*[^}]+\s*,?)+)}\s*.*\s*;'
    re_mat_pat_c = re.compile(re_mat_pat)
    re_mem_pat = '\s*((?:uint\d+_t)+)\s+(\w+)\s*(?:\[(\d+)\])?\s*;\s*'
    
    matches = re_mat_pat_c.finditer(format_rawcontent)
    for m in matches:
        tname = m.group(1)
        tstr = m.group(2)
        tmembers = tstr.splitlines()
        tlist = []
        
        for rmem in tmembers:
            m = re.search(re_mem_pat, rmem)
            if m is not None:
                new_mem = (m.group(1), m.group(2), m.group(3))
                tlist.append(new_mem)
        
        substruct_types[tname] = tlist
    
    return substruct_types

def parse_log_format(format_filename):
    with open(format_filename) as f:
        format_rawcontent = f.read()
    format_rawcontent = rewrite_number_types(format_rawcontent)

    log_types = parse_enums_to_list(format_rawcontent, "LOG_TYPE")
    log_tiers = parse_enums_to_list(format_rawcontent, "LOG_TIER")
    log_valid = parse_enums_to_list(format_rawcontent, "LOG_VALID")
    
    log_psubject = parse_enums_to_list(format_rawcontent, "PAYLOAD_SUBJECT")
    log_paction = parse_enums_to_list(format_rawcontent, "PAYLOAD_ACTION")
    log_pobject = parse_enums_to_list(format_rawcontent, "PAYLOAD_OBJECT")
    
    substruct_types = parse_substruct_types_to_dict(format_rawcontent)
    payload_types = parse_payload_types_to_list(format_rawcontent, log_types, substruct_types)
    
    log_format = {}
    log_format['types'] = log_types
    log_format['tiers'] = log_tiers
    log_format['valid'] = log_valid
    log_format['psubject'] = log_psubject
    log_format['paction'] = log_paction
    log_format['pobject'] = log_pobject
    log_format['ptypes'] = payload_types
    log_format['sstypes'] = substruct_types
    
    return log_format

def translate(log_filename, log_format, err_filename):
    in_file = open(log_filename) if log_filename != '__stdin' else sys.stdin
    cur = 1
    with in_file as f, open(err_filename, 'w') as ef:
        while True:
            rdata = f.readline()
            if not rdata: break
            if rdata.isspace(): continue
            
            rdata_bin = rawlog_to_bytesio(rdata)
            ld_raw = CursoredData(rdata_bin)
            log = cursored_data_to_log(log_format['ptypes'], ld_raw)
            
            err = 0
            try:
                rlog = transform_log_to_readable(log_format, log)
            except:
                ef.write('[-] Translation failed at line ' + str(cur) + '.\n')
                ef.write('[!] Reason: \n' + str(log) + '\n')
                err = 1
            
            cur += 1
            
            yield log, rlog, err

def get_create_table_qstring(payload_type):
    qstr = 'create table ?? ('
    col_list = []
    for tuple in payload_type:
        if tuple[2] is not None:
            for i in range(int(tuple[2])):
                col_list.append(tuple[1].replace('.', '__') + '_' + str(i) + ' varchar')
        else:
            col_list.append(tuple[1].replace('.', '__') + ' varchar')
    qstr += ','.join(col_list)
    qstr += ');'
    return qstr

def get_insert_into_qstring(flattened_log):
    qstr = 'insert into ?? values('
    col_list = []
    for i in range(0, len(flattened_log)):
        col_list.append('?')
    qstr += ','.join(col_list)
    qstr += ');'
    return qstr

def teeprint(exp, f):
    print(str(exp))
    f.write(str(exp) + '\n')

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print('Usage: python translate.py [log file name: optional/default->stdin] [format file name: optional/default->log_format.h]')
    else:
        log_filepath = sys.argv[1] if len(sys.argv) > 1  else "__stdin"
        format_filename = sys.argv[2] if len(sys.argv) > 2 else "log_format.h"
        
        if os.path.isdir(log_filepath):
            log_filename = log_filepath + '/log.txt'
        else:
            log_filename = log_filepath
        
        logdir = './result/' + log_filepath + '/'
        if not os.path.exists(logdir):
            os.makedirs(logdir)
        
        err_filename = logdir + 'error.txt'
        
        with open('translate-log.txt', 'a') as f:
            teeprint('[!] Target name is [' + log_filename + ']...', f)
            teeprint('[!] Parsing log format named [' + format_filename + ']...', f)
            formats = parse_log_format(format_filename)
            logs_gen = translate(log_filename, formats, err_filename)
            
            db_filename = logdir + 'result.db'
            if os.path.exists(db_filename):
                os.remove(db_filename)
            conn = sl3.connect(db_filename)
            cs = conn.cursor()
            
            i = 0
            for ltype in formats['types']:
                cs.execute(get_create_table_qstring(formats['ptypes'][i]).replace('??', ltype))
                i += 1
            
            gfile = open(logdir + 'plain-all.txt', 'w')
            
            teeprint('[!] Starting...', f)
            now = datetime.now()
            cur = 0
            total_errors = 0
            for raw_log, readable_log, error_occurred in logs_gen:
                total_errors += error_occurred
                save_log(gfile, readable_log)
                fdict = flatten_dict(readable_log, True)
                cs.execute(get_insert_into_qstring(fdict).replace('??', readable_log['type']), [v for k, v in fdict.items()])
     
                cur += 1
                if cur % 1000 == 0:
                    print('[!] Processed line ' + str(cur) + '.', end='\r')
                    conn.commit()

            later = datetime.now()
            teeprint('\n[!] There was(were) {} error line(s).'.format(total_errors), f)
            teeprint('[+] Finished.', f)
            teeprint('[!] It took: ' + str((later-now).total_seconds()) + ' secs\n', f)
        
