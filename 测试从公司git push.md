# coding: utf-8
from mark_source_root import * 
from sdl_basic.sdl_basic import *


class Local_Var():
    ##每次循环前不必初始化的变量
    #循环间隔时间（秒）
    loop_interval = 60
    #各 kong-xxx 对应域名
    domain_kong_dict = {"kong-c": "passenger.t3go.cn",
                        "kong-b-pri": "webapi-b.t3go.net",
                        "kong-vehicle-2": "vehicle.t3go.cn",
                        "kong-b": "gateway.t3go.cn"}

    #记录本轮执行报错告警
    warn_list = []

def InsertUeba_b_warn_list(data_dict_list):
    """入 t3_ueba_b_warn_list 表 """
    try:
        _db_con = DB_Conn(DB_INFO_SDL)
        #查询本次规则在SOC表种的详情
        _these_group_ids = ",".join(set([d.get('group_id') for d in data_dict_list]))
        soc_t3_ueba_conf_rules = ParseDBToDict_List(DB_Conn(DB_INFO_UEBA), f"""SELECT * FROM soc_ueba.t3_ueba_conf_rules WHERE group_id IN {ConvertToStrTuple(_these_group_ids)}  ; """)
        soc_t3_ueba_conf_rules_dict = dict()
        for e_r in soc_t3_ueba_conf_rules.get("data"):
            if soc_t3_ueba_conf_rules_dict.get(e_r.get("group_id")) == None :
                soc_t3_ueba_conf_rules_dict[e_r.get("group_id")] = dict()
            if soc_t3_ueba_conf_rules_dict.get(e_r.get("group_id")).get(str(e_r.get("monitor_interval"))) == None:
                soc_t3_ueba_conf_rules_dict[e_r.get("group_id")][str(e_r.get("monitor_interval"))] = e_r
        
        #记录本次循环是否有新增记录
        for _j in data_dict_list:
            dis_obj_type = "用户/账号" if len(str(_j.get("object_id"))) == 32 else "IP"
            monitor_obj = "该网关所有API" if str(_j.get("url")) == 'all' else _j.get("url")
            dis_obj_name = str(_j.get("object_id"))
            hit_wi_rule = soc_t3_ueba_conf_rules_dict.get(_j.get("group_id")).get(_j.get("interval")).get("id")
            fs_msg_id = calculation_md5(str(_j).encode('utf-8'))
            
            _SQL_TPL = f""" INSERT INTO `sdl_srv_db`.`t3_ueba_b_warn_list` (`dis_obj_type`, `monitor_obj`,`dis_obj_name`, `hit_wi_rule`, `fs_msg_id`, `warnTime_generate`,`warnTime_send`, `source`, `act_cnt`) VALUES 
            ('{dis_obj_type}',
            '{monitor_obj}',
            '{dis_obj_name}',
            '{hit_wi_rule}',
            '{fs_msg_id}',
            '{str(_j.get("update_time"))}',
            '{str(_j.get("update_time"))}',
            'hubble',
            '{str(_j.get("cnt"))}'); """
            _u_r = DB_ChangeSql(_db_con, _SQL_TPL, True, False)
            _new_flag = False
            if _db_con.affected_rows() > 0:
                _new_flag = True
            if _u_r.get("code") != 200 and "Duplicate entry" not in str(_u_r.get('data').get('summary')):
                _u_r["SQL"] = _SQL_TPL
                Local_Var.warn_list.append(_u_r)
        _db_con.commit()
        _db_con.close()
        
        return _new_flag
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def Insert_eagle_send_file_warn_list(data_dict_list):
    """接收 ParseFsMsgToSocUeba_b_warn_list 方法解出的数据结构、入 t3_ueba_b_warn_list 表 """
    try:
        _db_con = DB_Conn(DB_INFO_SDL)
        #记录本次循环是否有新增记录
        _new_flag = False
        for _j in data_dict_list:
            _SQL_TPL = f""" INSERT INTO `sdl_srv_db`.`t3_eagle_send_file_warn_list` (`eagle_event_id`, `dis_obj_type`, `monitor_obj`,`dis_obj_name`, `explain_auto`, `hit_wi_rule`, `fs_msg_id`, `warnTime_generate`, `warnTime_send`, `source`, `act_cnt`)
            VALUES ('{str(_j.get("eagle_event_id"))}', '{str(_j.get("dis_obj_type"))}',
            '{str(_j.get("monitor_obj"))}',
            '{str(_j.get("dis_obj_name"))}',
            '{str(_j.get("explain_auto"))}',
            '{str(_j.get("hit_wi_rule"))}',
            '{str(_j.get("fs_msg_id"))}',
            '{str(_j.get("warnTime_generate"))}',
            '{str(_j.get("warnTime_send"))}',
            '{str(_j.get("source"))}',
            '{str(_j.get("act_cnt"))}'); """
            _u_r = DB_ChangeSql(_db_con, _SQL_TPL, True, False)
            if _db_con.affected_rows() > 0:
                _new_flag = True
            if _u_r.get("code") != 200 and "Duplicate entry" not in str(_u_r.get('data').get('summary')):
                _u_r["SQL"] = _SQL_TPL
                Local_Var.warn_list.append(_u_r)
        _db_con.commit()
        _db_con.close()
        
        return _new_flag
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def Insert_Mail_warn_list(data_dict_list):
    """接收 ParseFsMsgToSocUeba_b_warn_list 方法解出的数据结构、入 t3_ueba_b_warn_list 表 """
    try:
        _db_con = DB_Conn(DB_INFO_SDL)
        #记录本次循环是否有新增记录
        _new_flag = False
        for _j in data_dict_list:
            _SQL_TPL = f""" INSERT INTO `sdl_srv_db`.`t3_mail_warn_list` (`dis_obj_type`, `trust_ip`, `action`, `monitor_obj`,`dis_obj_name`, `explain_auto`, `hit_wi_rule`, `fs_msg_id`, `warnTime_generate`, `warnTime_send`, `source`, `act_cnt`,`suc_login_cnt`)
            VALUES ('{str(_j.get("dis_obj_type"))}',
            '{str(_j.get("trust_ip"))}',
            '{str(_j.get("action"))}',
            '{str(_j.get("monitor_obj"))}',
            '{str(_j.get("dis_obj_name"))}',
            '{str(_j.get("explain_auto"))}',
            '{str(_j.get("hit_wi_rule"))}',
            '{str(_j.get("fs_msg_id"))}',
            '{str(_j.get("warnTime_generate"))}',
            '{str(_j.get("warnTime_send"))}',
            '{str(_j.get("source"))}',
            '{str(_j.get("act_cnt"))}',
            '{str(_j.get("suc_login_cnt"))}') ; """
            _u_r = DB_ChangeSql(_db_con, _SQL_TPL, True, False)
            if _db_con.affected_rows() > 0:
                _new_flag = True
            if _u_r.get("code") != 200 and "Duplicate entry" not in str(_u_r.get('data').get('summary')):
                _u_r["SQL"] = _SQL_TPL
                Local_Var.warn_list.append(_u_r)
        _db_con.commit()
        _db_con.close()
        
        return _new_flag
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def ParseFsMsgToSocUeba_b_warn_list(msg_list):
    """解析飞书 审计日志告警 群消息、生成符合 InsertUeba_b_warn_list 方法入 t3_ueba_b_warn_list 库的数据结构"""
    data_dict_list = []
    _warn_time_pattern = r'告警时间: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    _uuid_pattern = r'[0-9a-fA-F]{32}'
    _ipv4_pattern = r'(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'
    _ipv6_pattern = r'(\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b)'
    #_url_pattern = r'https?://[\w\.-]+(:\d+)?(/[\w\.-]*)*'
    
    for i in msg_list:
        try:
            _this_warn_dict = dict(source="fs",
                                   fs_msg_id=str(i.get("message_id")),
                                   explain_auto="",
                                   warnTime_send=ParseStampToDate(i.get("create_time")),
                                   warnTime_generate=ParseStampToDate(i.get("create_time"))
                                   )
            if (type(i.get("sender")) == dict and (str(i.get("sender").get("id")) == "cli_c08abc1da138d00f")) or len(re.findall("告警服务: 审计日志告警", str(i.get("body")))) > 0 :
                #判断是否是数据服务机器人发出来的消息
                _content = i.get("body").get("content")
            else:
                continue
            #if str(i.get("message_id")).lower() in ('om_957f2195e7ac3474a8c658131f950ee0'):
                #pass
            if len(_content.split("\\n")) < 4:
                #2024-4-10 消息格式可能不以\\n分割、尝试转dict然后用join连接
                _content_dict_list = ConverDumpStrToJson(_content).get("content")
                for lll in _content_dict_list:
                    _this_warn_dict['explain_auto'] = _this_warn_dict.get('explain_auto') + str(lll[0].get("text")) if len(lll) > 0 else _this_warn_dict.get('explain_auto')
                
                _tmp_user = re.findall(_uuid_pattern, _content_dict_list[3][0].get("text"))
                _this_warn_dict['dis_obj_type'] = '用户/账号' if len(_tmp_user) > 0 else 'IP'
                _this_warn_dict['dis_obj_name'] = _tmp_user[0] if len(_tmp_user) > 0 else _content_dict_list[3][1].get("text")
                #_this_warn_dict['warnTime_generate'] = str(_content_dict_list[1][0].get("text")).replace("告警时间:", "").strip()
                #2024-5-20 正则报错修复
                try:
                    if len(_content_dict_list[5]) > 1:
                        _this_warn_dict['monitor_obj'] = _content_dict_list[5][1].get("text")
                    else :
                        _this_warn_dict['monitor_obj'] = '该网关所有API'
                except Exception as e:
                    _err_info = DictException(e)
                    _this_warn_dict['monitor_obj'] = '解析 ' + str(_content_dict_list[5]) + " 报错: " + str(_err_info)
                    print("正则解析IM告警群消息\n"+str(_content_dict_list)+"\n报错: \n"+str(_err_info))
                try:
                    _name = _content_dict_list[2][0].get("text").strip().strip("审计规则: ")
                    if '近5分' in _content_dict_list[6][0].get("text"):
                        _interval = '-+-+-5'
                    elif '近60分' in _content_dict_list[6][0].get("text"):
                        _interval = '-+-+-60'
                    elif '近一天' in _content_dict_list[6][0].get("text"):
                        _interval = '-+-+-1440'
                    else:
                        _interval = ''
                    _this_warn_dict['hit_wi_rule'] = Local_Var.soc_audit_rule_dict.get(_name+_interval)
                except:
                    _this_warn_dict['hit_wi_rule'] = '-1'
                #解实际触警次数
                try:
                    _this_warn_dict['act_cnt'] = _content_dict_list[6][0].get("text").split(":")[-1].strip()
                except:
                    _this_warn_dict['act_cnt'] = '-1'
                data_dict_list.append(_this_warn_dict)

                #2024-4-10 END
            else:
                #将通知消息简化、记录摘要、记入 explain_auto 字段
                for ttt in ConverDumpStrToJson(_content).get("content")[0]:
                    if ttt.get("text") != None:
                        _this_warn_dict['explain_auto'] = _this_warn_dict.get('explain_auto') + str(ttt.get("text"))
                
                for ttt in ConverDumpStrToJson(_content).get("content")[0]:
                    #解析被监控API
                    if ttt.get("tag") == 'a' and str(ttt.get("text")).startswith("http") and "天机" not in str(ttt.get("text")) :
                        _this_warn_dict['monitor_obj'] = str(ttt.get("text"))
                        break
                else:
                    #没解到、给个空key、避免后面拿不到key报错
                    _this_warn_dict['monitor_obj'] = ''
                _tmp = re.findall(_warn_time_pattern, _content)
                _this_warn_dict['warnTime_generate'] = _tmp[0] if len(_tmp) > 0 else ''
                
                #判断触警对象类型（用户、IP）
        
                _tmp = _content.split("\\n")[3]
                if len(re.findall(_uuid_pattern, _tmp)) > 0 :
                    _this_warn_dict['dis_obj_type'] = '用户/账号'
                    _this_warn_dict['dis_obj_name'] = re.findall(_uuid_pattern, _tmp)[0]
                elif len(re.findall(_ipv4_pattern, _tmp)) > 0 or len(re.findall(_ipv6_pattern, _tmp)) > 0 :
                    _this_warn_dict['dis_obj_type'] = 'IP'
                    try:
                        _this_warn_dict['dis_obj_name'] = re.findall(_ipv4_pattern, _tmp)[0]
                    except:
                        _this_warn_dict['dis_obj_name'] = re.findall(_ipv6_pattern, _tmp)[0]
                else:
                    _this_warn_dict['dis_obj_type'] = '待定'
                    _this_warn_dict['dis_obj_name'] = _tmp.replace('"', '').split(":")[-1]
                #判断检出规则
                try:
                    _name = _content.split("\\n")[2].split(":")[-1].strip()
                    if '近5分' in _content.split("\\n")[-3]:
                        _interval = '-+-+-5'
                    elif '近60分' in _content.split("\\n")[-3]:
                        _interval = '-+-+-60'
                    elif '近一天' in _content.split("\\n")[-3]:
                        _interval = '-+-+-1440'
                    else:
                        _interval = ''
                    _this_warn_dict['hit_wi_rule'] = Local_Var.soc_audit_rule_dict.get(_name+_interval)
                except:
                    _this_warn_dict['hit_wi_rule'] = '-1'
                #解实际触警次数
                try:
                    _this_warn_dict['act_cnt'] = re.findall("\d+", _content.split("\\n")[-3].split("次数")[-1])[0]
                except:
                    _this_warn_dict['act_cnt'] = '-1'
                data_dict_list.append(_this_warn_dict)

        except Exception as e:
            err_info = DictException(e)
            Local_Var.warn_list.append(err_info)
            #return list()
    return data_dict_list


def ParseFsMsgToSocEagle_send_file_warn_list(msg_list):
    """解析飞书 审计日志告警 群消息、生成符合 Insert_eagle_send_file_warn_list 方法入 t3_eagle_send_file_warn_list 库的数据结构"""
    try:
        
        data_dict_list = []
        _warn_time_pattern = r'告警时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2})'
        _hit_cnt_patternr = r'外发\d个'
        #_uuid_pattern = r'[0-9a-fA-F]{32}'
        #_url_pattern = r'https?://[\w\.-]+(:\d+)?(/[\w\.-]*)*'
        
        for i in msg_list:
            #亿格云云枢数据安全告警通知、敏感数据敏感文件外发告警通知-解析方法
            _this_warn_dict = dict(act_cnt="-1", source="fs", dis_obj_type="用户/账号", explain_auto="", monitor_obj="", action="", dis_obj_name="", eagle_event_id="", hit_wi_rule="", warnTime_generate="", warnTime_send="", fs_msg_id=str(i.get("message_id")))
            if len(re.findall("亿格云云枢数据安全告警通知", str(i.get("body")))) > 0 and len(re.findall("敏感数据敏感文件外发告警通知", str(i.get("body")))) > 0 :
                _content = i.get("body").get("content")
                for ttt in ConverDumpStrToJson(_content).get("elements")[0]:
                    #解析被监控文件
                    if ttt.get("text") != None:
                        #将通知消息简化、记录摘要、记入 explain_auto 字段
                        _this_warn_dict['explain_auto'] = _this_warn_dict.get('explain_auto') + str(ttt.get("text"))
                    if ttt.get("tag") == 'text' :
                        for uuu in str(ttt.get("text")).split("\n"):
                            if str(uuu).startswith("告警内容"):
                                _this_warn_dict['monitor_obj'] = str(uuu).split("个敏感文件:")[-1].strip("\n").strip()
                                _this_warn_dict['action'] = str(uuu).strip("告警内容：使用").split("，外发")[0]
                                _this_warn_dict['act_cnt'] = re.findall(_hit_cnt_patternr, uuu)[0].strip("外发").strip("个") if len(re.findall(_hit_cnt_patternr, uuu)) > 0 else '-1'
                                continue
                            elif str(uuu).startswith("告警对象"):
                                _this_warn_dict['dis_obj_name'] = str(uuu).strip("告警对象：").strip("\n").strip()
                                continue
                            elif str(uuu).startswith("事件ID"):
                                _this_warn_dict['eagle_event_id'] = str(uuu).strip("事件ID：").strip("\n").strip()
                                continue
                            elif str(uuu).startswith("事件名称"):
                                #判断检出规则
                                _this_warn_dict['hit_wi_rule'] = str(uuu).strip("事件名称：").strip("\n").strip()
                                continue
                
                _this_warn_dict['warnTime_generate'] = re.findall(_warn_time_pattern, _content)[0] if len(re.findall(_warn_time_pattern, _content)) > 0 else ''
                _this_warn_dict['warnTime_send'] = re.findall(_warn_time_pattern, _content)[0] if len(re.findall(_warn_time_pattern, _content)) > 0 else ''
                
                data_dict_list.append(_this_warn_dict)
            
            else:
                #TODO: 可将该群后续其他告警
                pass
        return data_dict_list
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return list()


def loop_fetch_fs_audit_warn_newest_msg(start_time=None):
    #根据 soc 缓存的最后一次更新日期、拉取后续最新FS 告警
    try:
        PrintBeautiJson('', True, f""" 开始从hubble获取最新api调用量告警日志...""")
        #2025-3-19 钉钉告警群不支持获取历史消息（付费），改从 doris 获取最新告警记录
        if len(sys.argv) == 1:
            #检查当前已获取最新记录事件
            _newest_warn_time = str(ParseDBToDict_List(DB_Conn(DB_INFO_SDL), """SELECT MAX(warnTime_generate) as max_warn_time FROM sdl_srv_db.t3_ueba_b_warn_list; """).get("data")[0].get('max_warn_time'))
            #查询 t3go_datalake.dwd_ops_elk_audit_log_warn_detail_ds
            _query_sql = f"""select * from t3go_datalake.dwd_ops_elk_audit_log_warn_detail_ds 
            where is_warn='1' AND ds >= '{_newest_warn_time.split(" ")[0]}' AND update_time >= '{_newest_warn_time}' ; """
            
            #dl_result = HubbleWeb_DownLoad(sql=_query_sql, dl_path='./', dl_name='tmp_api_warn_rcds.xlsx', engine="doris")
            qs_result = HubbleWeb_Query(sql=_query_sql, engine="doris")
            if qs_result.get("code") != 200:
                return False
            elif len(qs_result.get("data")) == 0:
                return new_flag
            #有数据、入库
            _insert_resul = InsertUeba_b_warn_list(qs_result.get("data"))
        else:
            print(str( dict(code=500, data=None, msg='飞书下线、暂不支持手动执行，改造中...')))
            return False
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def loop_fetch_fs_dlp_warn_newest_msg(start_time=None):
    #根据soc 缓存的最后一次更新日期、拉取后续最新FS 告警
    return '飞书群停用、排期改从亿格云后台拉取最新数据'
    try:
        if start_time in (None, ''):
            LastUpdateDate = Redis_Read(key="FS_DLP_WARN_LAST_UPDATE_TIME", num=10).get("data")
            if LastUpdateDate == None :
                FeishuNotifyByMobile("18013827125", "因 SOC REDIS 10号库缺失 KEY=FS_DLP_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                print("因 SOC REDIS 10号库缺失 KEY=FS_DLP_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                sys.exit()
            try:
                LastUpdate_date = int(LastUpdateDate)
            except:
                FeishuNotifyByMobile("18013827125", "因 SOC REDIS 10号库缺失 KEY=FS_DLP_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                print("因 SOC REDIS 10号库缺失 KEY=FS_DLP_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                sys.exit()
        else:
            LastUpdate_date = int(ParseDateToStamp(start_time))
        
        from datetime import datetime
        # 获取当前日期
        _cur_time = time.localtime()
        end_date = datetime(_cur_time.tm_year, _cur_time.tm_mon, _cur_time.tm_mday, _cur_time.tm_hour, _cur_time.tm_min, _cur_time.tm_sec)
        need_loop_date_fs = []
        # 如果是从指定时间开始，每 Local_Var.loop_interval 秒一个间隔、加到执行日期列表
        if len(sys.argv) == 2:
            need_loop_date_fs = []
            while LastUpdate_date < end_date.timestamp():
                need_loop_date_fs.append(dict(start_ts=LastUpdate_date, end_ts=LastUpdate_date+Local_Var.loop_interval))
                # 加 Local_Var.loop_interval 秒
                LastUpdate_date = LastUpdate_date + Local_Var.loop_interval
        else:
            need_loop_date_fs = [dict(start_ts=int(time.time()-Local_Var.loop_interval), end_ts=int(time.time()))]
        new_flag = 0
        for _each_date in need_loop_date_fs:
            PrintBeautiJson('', True, f""" 开始从IM群拉取 {ParseStampToDate(_each_date.get('start_ts'))} ~ {ParseStampToDate(_each_date.get('end_ts'))} 期间的 文件外发 告警日志...""")
            _fs_msg = FeishuQueryGroupMsg(group_name='信息安全综合监控告警', chat_id='oc_4b9edacbed5782d99bca8ba18744a530', start_ts=_each_date.get('start_ts'), end_ts=_each_date.get('end_ts'))
            if _fs_msg.get("code") != 200:
                #报错，记录日志继续
                _fs_msg["time_range"] = _each_date
                Local_Var.warn_list.append(_fs_msg)
                #将更新日期写入soc redis、
                #Redis_Write(key="FS_DLP_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
                #可能是IM服务器限流、等待30秒再试
                time.sleep(30)
                continue
            elif len(_fs_msg.get("data")) != 0:
                #有数据、清洗
                _this_resul = ParseFsMsgToSocEagle_send_file_warn_list(_fs_msg.get("data"))
                
                #入库
                if  Insert_eagle_send_file_warn_list(_this_resul) == True:
                    new_flag = new_flag + 1
                
                #将更新日期写入soc redis
                Redis_Write(key="FS_DLP_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
            else:
                #无报错、无数据、跳入下一次循环
                #将更新日期写入soc redis
                Redis_Write(key="FS_DLP_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
                continue
        return new_flag
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def ParseFsMsgToSocMail_warn_list(msg_list):
    """解析飞书 邮箱危险行为告警专用群 群消息、生成符合 Insert_Mail_warn_list 方法入 t3_mail_warn_list 库的数据结构"""
    try:
        
        data_dict_list = []
        #_warn_time_pattern = r'告警时间：(\d{4}-\d{2}-\d{2} \d{2}:\d{2})'
        #_uuid_pattern = r'[0-9a-fA-F]{32}'
        #_url_pattern = r'https?://[\w\.-]+(:\d+)?(/[\w\.-]*)*'
        _login_total_cnt_patternr = r'总共登录次数：\d+ 次'
        _login_suc_cnt_patternr = r'成功登录次数:\d+ 次'
        _mail_pattern = r"：.*@.*t3go.cn|:.*@.*t3go.cn"
        _ip_cnt_pattern = r"IP:\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        for i in msg_list:
            #sender 不是 邮箱危险行为告警 机器人发送的、忽略
            if i.get("sender").get("id") != 'cli_c08abc1da138d00f':
                continue
            #邮箱爆破告警通知-解析方法
            if len(re.findall("本次检测发现以下高危帐号存在暴力破解行为", str(i.get("body")))) > 0 :
                fs_msg_id = i.get("message_id")
                warnTime =ParseStampToDate(i.get("create_time"))
                
                _content = ConverDumpStrToJson(i.get("body").get("content")).get("text")
                
                monitor_MailObj_list = [str(d).strip("：").strip(":") for d in re.findall(_mail_pattern, _content)]
                if len(monitor_MailObj_list) == 0:
                    continue
                
                
                for ttt in _content.split("异常帐号"):
                    if len(re.findall(_mail_pattern, ttt)) == 0:
                        continue
                    #这是最终要入库的单条记录
                    _this_warn_dict = dict(suc_login_cnt=0, act_cnt=0, source="fs", dis_obj_type="IP", explain_auto="", monitor_obj="",
                                           action="未知", dis_obj_name="", eagle_event_id="", hit_wi_rule="暴力破解",
                                           warnTime_generate=warnTime, warnTime_send=warnTime, fs_msg_id=fs_msg_id)
                    _this_warn_dict['explain_auto'] = "\n".join(ttt.split("\n")[:-1]).replace("\t", "").strip(":")
                    #将通知消息简化、记录摘要、记入 explain_auto 字段
                    for uuu in ttt.split("\n\t"):
                        try:
                            if len(re.findall(_mail_pattern, uuu)) > 0:
                                _this_warn_dict['monitor_obj'] = re.findall(_mail_pattern, uuu)[0].strip("：").strip(":")
                            elif len(re.findall(_login_total_cnt_patternr, uuu)) > 0:
                                _this_warn_dict['act_cnt'] = re.findall(r"\d+", re.findall(_login_total_cnt_patternr, uuu)[0])[0]
                            elif len(re.findall(_login_suc_cnt_patternr, uuu)) > 0:
                                _this_warn_dict['suc_login_cnt'] = re.findall(r"\d+", re.findall(_login_suc_cnt_patternr, uuu)[0])[0]
                            elif len(re.findall(_ip_cnt_pattern, uuu)) > 0:
                                _this_warn_dict['dis_obj_name'] = _this_warn_dict.get("dis_obj_name") + "," + str(re.findall(_ip_cnt_pattern, uuu)[0].strip("IP:"))
                                if "是否可靠: yes" in uuu:
                                    _this_warn_dict['trust_ip'] = 'YES'
                                else:
                                    _this_warn_dict['trust_ip'] = 'NO'
                            
                        except Exception as e:
                            PrintBeautiJson(DictException(e), True, f""" {str(uuu)} 中无法解出爆破告警信息""")
                    
                    
                    if _this_warn_dict.get('suc_login_cnt') != 0:
                        _this_warn_dict['action'] = "YES"
                    else:
                        _this_warn_dict['action'] = "NO"
                    
                    _this_warn_dict['dis_obj_name'] = _this_warn_dict.get("dis_obj_name").strip(",")
                        
                    
                    #
                    data_dict_list.append(_this_warn_dict)
            
            else:
                #TODO: 可将该群后续其他告警
                pass
        return data_dict_list
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return list()


def loop_fetch_fs_Mail_warn_newest_msg(start_time=None):
    #根据soc 缓存的最后一次更新日期、拉取后续最新FS 告警
    try:
        if start_time in (None, ''):
            LastUpdateDate = Redis_Read(key="FS_MAIL_WARN_LAST_UPDATE_TIME", num=10).get("data")
            if LastUpdateDate == None :
                FeishuNotifyByMobile("18013827125", "因 SOC REDIS 10号库缺失 KEY=FS_MAIL_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                print("因 SOC REDIS 10号库缺失 KEY=FS_MAIL_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                sys.exit()
            try:
                LastUpdate_date = int(LastUpdateDate)
            except:
                FeishuNotifyByMobile("18013827125", "因 SOC REDIS 10号库缺失 KEY=FS_MAIL_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                print("因 SOC REDIS 10号库缺失 KEY=FS_MAIL_WARN_LAST_UPDATE_TIME、fetchHubbleWarnLog_ParseIntoSocTab.py脚本停止执行；\n要求格式：1704038400，10位整数时间戳（秒）。\n请补齐后重启")
                sys.exit()
        else:
            LastUpdate_date = int(ParseDateToStamp(start_time))
        
        from datetime import datetime
        # 获取当前日期
        _cur_time = time.localtime()
        end_date = datetime(_cur_time.tm_year, _cur_time.tm_mon, _cur_time.tm_mday, _cur_time.tm_hour, _cur_time.tm_min, _cur_time.tm_sec)
        # 每 Local_Var.loop_interval 秒一个间隔、加到执行日期列表
        need_loop_date_fs = []
        # 如果是从指定时间开始，每 Local_Var.loop_interval 秒一个间隔、加到执行日期列表
        if len(sys.argv) == 2:
            need_loop_date_fs = []
            while LastUpdate_date < end_date.timestamp():
                need_loop_date_fs.append(dict(start_ts=LastUpdate_date, end_ts=LastUpdate_date+Local_Var.loop_interval))
                # 加 Local_Var.loop_interval 秒
                LastUpdate_date = LastUpdate_date + Local_Var.loop_interval
        else:
            need_loop_date_fs = [dict(start_ts=int(time.time()-Local_Var.loop_interval), end_ts=int(time.time()))]
        new_flag = 0
        for _each_date in need_loop_date_fs:
            PrintBeautiJson('', True, f""" 开始从IM群拉取 {ParseStampToDate(_each_date.get('start_ts'))} ~ {ParseStampToDate(_each_date.get('end_ts'))} 期间的 邮箱被爆破 告警日志...""")
            _fs_msg = FeishuQueryGroupMsg(group_name='邮箱危险行为告警专用群', chat_id='oc_24a9cc7ea24e4510070174d86f9934d9', start_ts=_each_date.get('start_ts'), end_ts=_each_date.get('end_ts'))
            if _fs_msg.get("code") != 200:
                #报错，记录日志继续
                _fs_msg["time_range"] = _each_date
                Local_Var.warn_list.append(_fs_msg)
                #将更新日期写入soc redis、
                #Redis_Write(key="FS_MAIL_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
                ##可能是IM服务器限流、等待30秒再试
                #time.sleep(30)
                continue
            elif len(_fs_msg.get("data")) != 0:
                #有数据、清洗
                _this_resul = ParseFsMsgToSocMail_warn_list(_fs_msg.get("data"))
                
                #入库
                if  Insert_Mail_warn_list(_this_resul) == True:
                    new_flag = new_flag + 1
                
                #将更新日期写入soc redis
                Redis_Write(key="FS_MAIL_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
            else:
                #无报错、无数据、跳入下一次循环
                #将更新日期写入soc redis
                Redis_Write(key="FS_MAIL_WARN_LAST_UPDATE_TIME", value=int(_each_date.get("end_ts"))-10, num=10)
                continue
        return new_flag
    except Exception as e:
        err_info = DictException(e)
        Local_Var.warn_list.append(err_info)
        return False


def QueryIpInfoForBruteIP():
    #2024-5-18 判断哪些IP是新出现、不存在于 soc_ip_stack 表，然后通过阿里IP查询接口、解析当前IP信息、入 soc_ip_stack 表
    #（1）筛选 t3_mail_warn_list 、ip_query != yes 的IP记录、用 ip_stack 查询
    _no_query_ips = ParseDBToDict_List(DB_Conn(DB_INFO_SDL), """ SELECT id, dis_obj_name FROM sdl_srv_db.t3_mail_warn_list WHERE is_del !='yes' AND (ip_query != 'yes' OR ip_query IS NULL OR ip_base_info IS NULL OR ip_base_info = ''); """).get("data")
    if len(_no_query_ips) == 0:
        print("无待查询IP、跳过Aliyun IP查询~")
        return False
    _no_query_id_list = [str(d.get("id")) for d in _no_query_ips] #留着后面当 update 主键
    _no_query_ips_list = list(set(",".join([d.get("dis_obj_name") for d in _no_query_ips]).replace(",,", ",").split(",")))
    TO_BE_UPDATE_ip_base_info_dict = dict()
    for _each in _no_query_ips_list:
        _tmp = ip_stack_query(_each, _each, 'yes')
        if _tmp == False:
            #接口可能限流、暂停继续
            print("查询 "+str(_each)+"IP基本信息报错")
            time.sleep(2)
            continue
        TO_BE_UPDATE_ip_base_info_dict[_each] = dict(ip=_tmp.get("ip"), country=_tmp.get("country"), city=_tmp.get("city"), prov=_tmp.get("prov"), dist=_tmp.get("dist"),
                                                     longitude=_tmp.get("longitude"), latitude=_tmp.get("latitude"), srv_use=_tmp.get("srv_use"), mobile_use=_tmp.get("mobile_use"))
    #（2）将 TO_BE_UPDATE_ip_base_info_dict 中关于每条告警记录的IP位置信息、回写到 sdl_srv_db.t3_mail_warn_list 表
    _db_con = DB_Conn(DB_INFO_SDL)
    for _each2 in _no_query_ips:
        _need_renew_ip_info_list = []
        for _i in str(_each2.get("dis_obj_name")).split(","):
            if TO_BE_UPDATE_ip_base_info_dict.get(_i) == None:
                continue
            _need_renew_ip_info_list.append(TO_BE_UPDATE_ip_base_info_dict.get(_i))
        if len(_need_renew_ip_info_list) == 0:
            continue
        _s = Base64Encode(str(_need_renew_ip_info_list))
        u_sql = f""" UPDATE sdl_srv_db.t3_mail_warn_list A SET A.ip_base_info = '{_s}', ip_query='yes' WHERE A.id = '{_each2.get("id")}';"""
        _ur = DB_ChangeSql(_db_con, u_sql, True, False)
        if _ur.get("code") != 200 :
            _ur['SQL'] = u_sql
            Local_Var.warn_list.append(_ur)
    _db_con.commit()
    _db_con.close()
    


def MAIN():
    """程序主体"""
    start_time = time.time()
    PrintBeautiJson("", True, "开始执行~")
    
    #拉取最新审计规则列表
    _audit_rules = ParseDBToDict_List(DB_Conn(DB_INFO_UEBA), """ SELECT CONCAT(group_name, '-+-+-',monitor_interval) AS rule_name_interval, id FROM soc_ueba.t3_ueba_conf_rules WHERE is_del REGEXP 'no' ORDER BY id desc; """).get("data")
    Local_Var.soc_audit_rule_dict = dict()
    for i in _audit_rules:
        Local_Var.soc_audit_rule_dict[str(i.get("rule_name_interval"))] = i.get("id")
    del _audit_rules
    
    #DEBUG-单线程调试
    #loop_fetch_fs_audit_warn_newest_msg()
    #loop_fetch_fs_Mail_warn_newest_msg()
    
    #2024-8-14 接收cmd入参、执行指定任务
    if len(sys.argv)>1:
        print(sys.argv[1])
        Local_Var.loop_interval = 3600
        if str(sys.argv[1]).lower() == 'audit_warn':
            start_date = input("请输入要同步【审计日志告警群】消息的开始时间（YYYY-mm-dd HH-MM-SS）：")
            loop_fetch_fs_audit_warn_newest_msg(start_date)
        elif str(sys.argv[1]).lower() == 'mail_brute':
            start_date = input("请输入要同步【邮箱危险行为告警专用群】消息的开始时间（YYYY-mm-dd HH-MM-SS）：")
            loop_fetch_fs_Mail_warn_newest_msg(start_date)
        elif str(sys.argv[1]).lower() == 'dlp_file':
            start_date = input("请输入要同步【信息安全综合监控告警】消息的开始时间（YYYY-mm-dd HH-MM-SS）：")
            loop_fetch_fs_dlp_warn_newest_msg(start_date)
        else:
            print("""参数有误：\n
            audit_warn：同步【审计日志告警群】群消息
            mail_brute： 同步【邮箱危险行为告警专用群】群消息
            dlp_file：      同步【信息安全综合监控告警】群消息""")
            sys.exit()
    else:
        #2024-4-2 启用多线程
        with ThreadPoolExecutor(max_workers=5) as _pool :
            ##审计日志告警群、近 Local_Var.loop_interval 秒 内发出的告警消息
            ##TODO: 待对接钉钉群消息同步功能后开启
            _sub1 = _pool.submit(loop_fetch_fs_audit_warn_newest_msg)
            #2024-4-4 信息安全综合监控告警群、近 Local_Var.loop_interval 秒内发出的告警消息
            _sub2 = _pool.submit(loop_fetch_fs_dlp_warn_newest_msg)
            #2024-4-6 邮箱账号风险告警群、近 Local_Var.loop_interval 秒内发出的告警消息
            _sub3 = _pool.submit(loop_fetch_fs_Mail_warn_newest_msg)
            _sub1.result()
            _sub2.result()
            _sub3.result()
        #2024-4-2 END
    
    #更新爆破IP基本信息
    QueryIpInfoForBruteIP()
    
    
    PrintBeautiJson('', True, f"本轮耗时: {str(int(duration))} 秒 ")


if __name__ == '__main__':
    #debug
    
    MAIN()
