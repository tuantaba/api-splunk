#!/usr/bin/python
import urllib
import requests
import json
import time
from mysql.connector import MySQLConnection, Error
from mysql_dbconfig import read_db_config
import os
import logging
import uuid
from datetime import datetime, date, timedelta
import alert
from influxdb import InfluxDBClient
from concurrent.futures import ThreadPoolExecutor, as_completed


#InfluxDB
influx_minimum=100

chat_id = -xxxxxx

baseurl = 'https://x.x.x.x:8089/services/search/jobs'
username = 'xxxxx'
password = 'xxxxxx'
group_threshold_4xx = 1000
group_threshold_5xx = 300
default_threshold_4xx=15000
default_threshold_5xx=300
default_threshold_404=20000
default_threshold_400=15000
default_threshold_503=100
default_manager="svr"
count_log_warn = 100
source_ip = '*'
time_get_log = "5m"
time_splunk = " earliest=-" + time_get_log +" latest=now"
EXCLUDE_DOMAINS=' DOMAIN!="example.com"'
time_alert_to_live=30
msg_link_splunk=""


logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')
client = InfluxDBClient(influx_url, influx_port, influx_user, influx_pass, influx_db)

def influxdb_insert(metric):
    result = client.write(metric, {'db':influx_db},204, protocol='line')
        #    if result.status_code != 204:
        #        print >> sys.stderr, result.text
    return result



def sql_insert(session_id, domain, http_code, count, raw_log):
    query = "INSERT INTO sla_code(session_id, domain, http_code, count, raw_log) " \
            "VALUES(%s,%s,%s, %s, %s)"
    try:
        db_config = read_db_config()
        conn = None
        conn = MySQLConnection(**db_config)

        cursor = conn.cursor()
        args = (str(session_id), str(domain), http_code, count, str(raw_log))
        cursor.execute(query, args)
        #        if cursor.lastrowid:
        #            print('last insert id', cursor.lastrowid)
        #            logging.info('last insert id' + str(cursor.lastrowid))
        #        else:
        #            print('last insert id not found')
        #            logging.error('Error: ' + str(domain) + str(e))
        conn.commit()
    except Error as error:
        print(error)
    finally:
        cursor.close()
        conn.close()


def check_alert(domain, alert_type, default_threshold, _count, manager):
    baseurl= 'https://xxxxxxxx/sla/api/alert'
    username = 'xxxxxxx'
    password = 'xxxxxxxxx'
    auth = requests.auth.HTTPBasicAuth(username, password)
    response = requests.get(baseurl +"?domain="+domain+"&alert_type="+alert_type, auth=auth, verify=False)
    #print response.text
    results=json.loads(response.text)

    if  alert_type == '404':
        default_threshold = default_threshold_404
    elif alert_type == '400':
        default_threshold = default_threshold_400
    elif alert_type == '503':
        default_threshold = default_threshold_503
    elif alert_type == '500' and "admicro" in domain:
        default_threshold = 500
    else:
        print "DEBUG: func check_alert() var default_threshold nothing change"

    if len(results) == 0:
        print "API Alert: sub-domain is not exist,  no result with domain", domain
        print "Insert record"
        data = {
                "domain": domain,
                "alert_type": alert_type,
                "count": _count,
                "threshold": default_threshold,
                "manager": manager
                }
        headers = {"Content-Type": "application/json"}
        response = requests.post(baseurl, auth=auth, data=json.dumps(data),headers=headers, verify=False)

        response = requests.get(baseurl +"?domain="+domain+"&alert_type="+alert_type, auth=auth, verify=False)
        #print response.text
        results=json.loads(response.text)

    alert_time_in_db=results[0]['alert_time']
    manager=results[0]['manager']
    threshold=results[0]['threshold']

    if alert_time_in_db == "None" or alert_time_in_db == None:
        alert_yes=True
        return alert_time_in_db, alert_yes, manager, threshold
    else:
        print "_alert_time_in_db: in DB is", alert_time_in_db
        time_past=datetime.now()-timedelta(minutes=time_alert_to_live)
        alert_time_in_db = datetime.strptime(alert_time_in_db, '%Y-%m-%d %H:%M:%S')
        alert_yes=alert_time_in_db < time_past  #check time_DB da canh bao co <  hon time_past khong, neu  True -> canh bao
        print "alert_yes: is", alert_yes
        return alert_time_in_db, alert_yes, manager, threshold

def call_api_alert_manager(manager):
    baseurl= 'https://x.x.x.x/sla/api/alert/manager'
    username = 'vcbizflydcbm1'
    password = '2cbe607d896f9a0VCCorps93395154f9499'
    auth = requests.auth.HTTPBasicAuth(username, password)
    response = requests.get(baseurl +"?manager="+manager, auth=auth, verify=False)
    results=json.loads(response.text)

    if len(results) == 0:
        print "API Alert: no result with manager", manager
        print "Sysadmin add this manager into DB, table: sla_manager"

    chat_id=results[0]['chat_id']
    return chat_id


def alert_update_status(domain, alert_type, alert_time):
    baseurl= 'https://x.x.x.x/sla/api/alert'
    username = 'xxxx'
    password = 'xxxx'
    auth = requests.auth.HTTPBasicAuth(username, password)

    data = {
            "domain": domain,
            "alert_type": alert_type,
            "alert_time": alert_time

            }
    headers = {"Content-Type": "application/json"}
    response = requests.put(baseurl, auth=auth, data=json.dumps(data),headers=headers, verify=False)
    #print response.text

    if str(response.status_code) != '200' or str(response.status_code) != '201':
        print ("HTTP Request error, code", response.status_code)
        return False
    else:
        print response.text
        return True


def splunk_search_getdomain(search_command):
    search = search_command
    output_mode = 'json'
    max_count = 100000
    auth = requests.auth.HTTPBasicAuth(username, password)
    data = {
        "search": search,
        "output_mode": output_mode,
        "max_count": max_count,
    }

    response = requests.post(baseurl, auth=auth, data=data, verify=False)

    if str(response.status_code) != '200' or str(response.status_code) != '201':
        print ("HTTP Request error, code", response.status_code)
        exit;

    print response.text
    job_id = json.loads(response.text)['sid']
    print "job id from domain is: ", job_id
    # print response.text
    dispatchState = "UNKNOW"
    while dispatchState != "DONE" and dispatchState != "FAILED":
        response = requests.post(baseurl + "/" + job_id, data=data, auth=auth, verify=False)
        dispatchState = json.loads(response.text)['entry'][0]['content']['dispatchState']
        time.sleep(1)
        print "dispatchState from domain is:", dispatchState

    if dispatchState == "DONE":
        results_complete = False
        offset = 0
        results = list()
        while not results_complete:
            # data = {'output_mode': 'json'}
            response = requests.get(baseurl + "/" + job_id +
                                    '/results?count=50000&offset=' + str(offset),
                                    data=data, auth=auth, verify=False)
            json_load = json.loads(response.text)
            #        print len(json_load['results'])
            #        print response.text
            results += json_load['results']
            if len(json_load['results']) == 0:  # This means that we got all of the results
                results_complete = True
            else:
                offset += 50000
    get_domain_list = results
#    print "Function: splunk_search_getdomain()"
#    print results

    if len(results) == 0:
        print "=========================== No results"
        return "failed"
#    print raw_log
    return get_domain_list


def splunk_search_getlog(search_command):
    search = search_command
    output_mode = 'json'
    max_count = 100000
    auth = requests.auth.HTTPBasicAuth(username, password)
    data = {
        "search": search,
        "output_mode": output_mode,
        "max_count": max_count,
    }

    response = requests.post(baseurl, auth=auth, data=data, verify=False)

    if str(response.status_code) != '200' or str(response.status_code) != '201':
        print ("HTTP Request error, code", response.status_code)
        exit;

    print response.text
    job_id = json.loads(response.text)['sid']
    print "job id from domain is: ", job_id
    # print response.text
    dispatchState = "UNKNOW"
    while dispatchState != "DONE" and dispatchState != "FAILED":
        response = requests.post(baseurl + "/" + job_id, data=data, auth=auth, verify=False)
        dispatchState = json.loads(response.text)['entry'][0]['content']['dispatchState']
        time.sleep(1)
        print "dispatchState from domain is:", dispatchState

    if dispatchState == "DONE":
        results_complete = False
        offset = 0
        results = list()
        while not results_complete:
            # data = {'output_mode': 'json'}
            response = requests.get(baseurl + "/" + job_id +
                                    '/results?count=50000&offset=' + str(offset),
                                    data=data, auth=auth, verify=False)
            json_load = json.loads(response.text)
            #        print len(json_load['results'])
            #        print response.text
            results += json_load['results']
            if len(json_load['results']) == 0:  # This means that we got all of the results
                results_complete = True
            else:
                offset += 50000
    raw_log = []
    count_log = len(results)
    #    print results

    if len(results) == 0:
        print "=========================== No results"
        return "failed"

    if 1 < len(results):
        raw_log.append(results[0]['_raw'])

#    if 2 < len(results):
#        raw_log.append(results[1]['_raw'])

#    if 3 < len(results):
#        raw_log.append(results[2]['_raw'])
#    print "splunk_search: count_log is", count_log
#    print raw_log
    return raw_log


def get_splunk_log_from_domain(session_id, DOMAIN):
    global msg_link_splunk
    search = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + DOMAIN + EXCLUDE_DOMAINS + ' (HTTP_CODE=500 OR HTTP_CODE=501 OR HTTP_CODE=502 OR HTTP_CODE=503 OR HTTP_CODE=504 OR HTTP_CODE=404 OR HTTP_CODE=403 OR HTTP_CODE=402 OR HTTP_CODE=401 OR HTTP_CODE=400 ) ' + time_splunk + ' | top limit=20 HTTP_CODE'
    output_mode = 'json'
    max_count = 100000
    auth = requests.auth.HTTPBasicAuth(username, password)
    data = {
        "search": search,
        "output_mode": output_mode,
        "max_count": max_count,
    }

    response = requests.post(baseurl, auth=auth, data=data, verify=False)

    if str(response.status_code) != '200' or str(response.status_code) != '201':
        print ("HTTP Request error, code", response.status_code)
        exit;

    print response.text
    job_id = json.loads(response.text)['sid']
    print "job id from domain is: ", job_id
    # print response.text
    dispatchState = "UNKNOW"
    while dispatchState != "DONE" and dispatchState != "FAILED":
        response = requests.post(baseurl + "/" + job_id, data=data, auth=auth, verify=False)
        dispatchState = json.loads(response.text)['entry'][0]['content']['dispatchState']
        time.sleep(1)
        print "dispatchState from domain is:", dispatchState

    if dispatchState == "DONE":
        results_complete = False
        offset = 0
        results = list()
        #    DOMAIN_LIST = list()
        while not results_complete:
            # data = {'output_mode': 'json'}
            response = requests.get(baseurl + "/" + job_id +
                                    '/results?count=50000&offset=' + str(offset),
                                    data=data, auth=auth, verify=False)
            json_load = json.loads(response.text)
            #        print len(json_load['results'])
    #        print response.text
            results += json_load['results']
            if len(json_load['results']) == 0:  # This means that we got all of the results
                results_complete = True
            else:
                offset += 50000
            print results
    print "session_id is", session_id

    if len(results) == 0:
        print  "No results on {}" . format(DOMAIN)


    for result in results:
        have_result = False
        #        print result
        _http_code = result['HTTP_CODE']
        _count = int(result['count'])
        _percent = result['percent']
        print _http_code, _count, _percent
        #        print "type _count is ", type(_count)
        if (_http_code == '404' and _count > group_threshold_4xx) or (_http_code == '403' and _count > group_threshold_4xx) or (
                _http_code == '402' and _count > group_threshold_4xx) or (_http_code == '401' and _count > group_threshold_4xx) or (
                _http_code == '400' and _count > group_threshold_4xx):
            print "insert to DB 4xx, is on code ", _http_code

            search_getdomain= 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + DOMAIN + ' HTTP_CODE=' + str( _http_code) + time_splunk + ' | top limit=20 DOMAIN'

            _get_domain_list= splunk_search_getdomain(search_getdomain)
            print _get_domain_list

            print "Domain to get raw_log is", _get_domain_list[0]['DOMAIN'] #get raw_log in top 1 domain
            search_raw = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_get_domain_list[0]['DOMAIN']) + ' HTTP_CODE=' + str( _http_code) + time_splunk

            _get_domain_list= splunk_search_getdomain(search_getdomain)
            print _get_domain_list

            print "Domain to get raw_log is", _get_domain_list[0]['DOMAIN'] #get raw_log in top 1 domain
            search_raw = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_get_domain_list[0]['DOMAIN']) + ' HTTP_CODE=' + str( _http_code) + time_splunk

            raw_log = splunk_search_getlog(search_raw)
            if raw_log == "failed":
                print "Warning:  get log failed on", DOMAIN
            else:
                #               print raw_log
                have_result = True
                have_alert=False
                alert_type = _http_code
                manager_array = []
                alert_time_now=datetime.now()
                alert_time_now = alert_time_now.strftime('%Y-%m-%d %H:%M:%S')

                _alert_time, alert_yes, manager, threshold = check_alert(DOMAIN, alert_type, default_threshold_4xx, _count, default_manager)
                print "{} have code {} with threshold {}: ". format(DOMAIN,_http_code,threshold)

                logs = ""
                domains = "| domain      |  count   |   percent \n"
		svr_text = ""

                for _raw_log in raw_log:
                    _raw_log=_raw_log.replace("<", "N;")
                    _raw_log=_raw_log.replace(">", "N;")
                    _raw_log=_raw_log.replace("&", "N;")
                    logs = logs +  "   - " +_raw_log + "\n"
                print "logs is: ", logs
                for _result in _get_domain_list:
                    _domain =  _result['DOMAIN']
                    _count_each_domain =  _result['count']
                    _percent = int(round(float(_result['percent'])))

                    if int(_count_each_domain) > threshold:
                        each_domain_alert_time, each_domain_alert_yes, each_domain_manager, each_domain_threshold = check_alert(_domain, alert_type, default_threshold_4xx, _count_each_domain, manager)
                        if each_domain_alert_yes:
                            have_alert=True
                            manager_array.append(each_domain_manager)
                            result_alert_update=alert_update_status(_domain, alert_type, alert_time_now)
                            if result_alert_update:
                                print "alert_update_status: {} Update status ok" . format(_domain)
                            else:
                                print "alert_update_status: {} Update status false" . format(_domain)

			    splunk_get_svr = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_domain) + ' HTTP_CODE=' + str( _http_code) + ' SERVER_IPPORT=* '  + time_splunk + ' | top limit=20 SERVER_IPPORT'

                            print "command to get svr: ", splunk_get_svr
                            _get_svr_list = splunk_search_getdomain(splunk_get_svr)
                            print _get_svr_list
                            if _get_svr_list != "failed":
                                msg_search_splunk = 'search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_domain) + ' HTTP_CODE=' + str( _http_code) + ' SERVER_IPPORT=*  IP_SOURCE=* ' +  ' earliest=-1h latest=now'
                                msg_search_splunk = urllib.quote(msg_search_splunk)
                                msg_link_splunk = "https://10.3.65.136:8000/en-US/app/search/search?q=" + msg_search_splunk
                                history_graph = "https://grafana.cnht.vn/d/d3VJnJSMz/ddos-sla-site?var-http=" + str( _http_code) + "&var-domain=" + str(_domain)

#                                svr_text = svr_text + _domain + " <a href='" + msg_link_splunk + " '> Trouble  </a>" + "- <a href='" + history_graph + " '> History </a> \n"
                                svr_text = svr_text + " <a href='" + msg_link_splunk + " '>" +  _domain + " </a>" + "\n"            
                                svr_text = svr_text \
                                        + " |  SERVER_PORT   |   count  |  percent  | \n"
                                for _svr in _get_svr_list:
                                    svr_text = svr_text \
                                        + " |" + _svr['SERVER_IPPORT'] + " | " + _svr['count'] + " | " + str(int(round(float(_svr['percent'])))) + "%" + " | \n"
                            manager = each_domain_manager

                    if int(_count_each_domain) >= influx_minimum:
                        metric_name=MEASUREMENT + ',' + 'domain=' + str(_domain) + ',' +  'http=' + str(_http_code)  +',' +  'manager=' + str(manager) +  ' value=' + str(_count_each_domain)
                        print "influx_metric is", metric_name
                        influxdb_insert(metric_name)

                    if int(_count_each_domain) >= count_log_warn:
                        domains = domains + "|" + _domain + " |  " +  str(_count_each_domain) + "|   " + str(_percent) + "%\n"
#                        domains = domains + "|" +  _domain +  " |  " +  str(_count_each_domain) + "|   " + str(_percent) + "%  |" + " <a href=\"" + msg_link_splunk + "\"> Trouble  </a>" + " <a href=\"" + history_graph + "\"> History </a> \n"

                msg = "<strong>Domain:</strong> {} \n" \
                            "    - Error: {}\n" \
                            "    - Count: {} / {}\n" \
                            "{}\n" \
                            "{}\n" \
                            "<pre><code> \n" \
                            "{}\n" \
                            "</code></pre>". format(DOMAIN,_http_code,_count,time_get_log,domains,str(svr_text),logs)
                sql_insert(session_id, DOMAIN, alert_type, _count, raw_log)

                if _alert_time == False:
                    print "API Alert: no value setup on splunk or DB, sysadmin need setup now!"
                elif alert_yes == True:
                    print "API Alert: API update status & notify"
                    if have_alert:
                        print  "OK:  Alert is", have_alert
                        print "Send notify"
                        print msg
#                        print chat_id
                        manager_array = list(dict.fromkeys(manager_array))
                        for _manager in manager_array:
                            print "each_domain: with manager {}" . format(_manager)
                            chat_id = call_api_alert_manager(_manager)
                            alert.send_telegram(msg, chat_id)
                    else:
                        print "Warn:  Alert is", alert
                else:
                    print "API Alert: sleep to {}m, don't alert anything!" . format(time_alert_to_live)

        if (_http_code == '500' and _count > group_threshold_5xx) or (_http_code == '501' and _count > group_threshold_5xx) or (
                _http_code == '502' and _count > group_threshold_5xx) or (_http_code == '503' and _count > group_threshold_5xx) or (_http_code == '504' and _count > group_threshold_5xx):
            have_result = True
            print "insert to DB 5xx, on code:", _http_code

            search_getdomain= 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + DOMAIN + ' HTTP_CODE=' + str( _http_code) + time_splunk + ' | top limit=20 DOMAIN'

            _get_domain_list= splunk_search_getdomain(search_getdomain)
            print _get_domain_list

            print "Domain to get raw_log is", _get_domain_list[0]['DOMAIN'] #get raw_log in top 1 domain
            search_raw = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_get_domain_list[0]['DOMAIN']) + ' HTTP_CODE=' + str( _http_code) + time_splunk

            raw_log = splunk_search_getlog(search_raw)
            if raw_log == "failed":
                print "Warning:  get log failed on", DOMAIN
            else:
                #               print raw_log
                have_result = True
                have_alert=False
                alert_type = _http_code
                manager_array = []
                alert_time_now=datetime.now()
                alert_time_now = alert_time_now.strftime('%Y-%m-%d %H:%M:%S')

                _alert_time, alert_yes, manager, threshold = check_alert(DOMAIN, alert_type, default_threshold_5xx, _count, default_manager)
                print "{} have code {} with threshold {}: ". format(DOMAIN,_http_code,threshold)

                logs = ""
                domains = "| domain      |  count   |   percent \n"
                svr_text = ""

                for _raw_log in raw_log:
                    _raw_log=_raw_log.replace("<", "N;")
                    _raw_log=_raw_log.replace(">", "N;")
                    _raw_log=_raw_log.replace("&", "N;")
                    logs = logs +  "   - " +_raw_log + "\n"
                print "logs is: ", logs
                for _result in _get_domain_list:
                    _domain =  _result['DOMAIN']
                    _count_each_domain =  _result['count']
                    _percent = int(round(float(_result['percent'])))

                    if int(_count_each_domain) > threshold:
                        each_domain_alert_time, each_domain_alert_yes, each_domain_manager, each_domain_threshold = check_alert(_domain, alert_type, default_threshold_5xx, _count_each_domain, manager)
                        if each_domain_alert_yes:
                            have_alert=True
                            manager_array.append(each_domain_manager)
                            result_alert_update=alert_update_status(_domain, alert_type, alert_time_now)
                            if result_alert_update:
                                print "alert_update_status: {} Update status ok" . format(_domain)
                            else:
                                print "alert_update_status: {} Update status false" . format(_domain)
                            #Get error server
                            splunk_get_svr = 'Search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_domain) + ' HTTP_CODE=' + str( _http_code) + ' SERVER_IPPORT=* '  + time_splunk + ' | top limit=20 SERVER_IPPORT'
                            print "command to get svr: ", splunk_get_svr
                            _get_svr_list = splunk_search_getdomain(splunk_get_svr)
                            print _get_svr_list
                            if _get_svr_list != "failed":
                                msg_search_splunk = 'search index=vccl_dc_svr_haproxy FRONTEND=* NOT "TCP"' + ' DOMAIN=' + str(_domain) + ' HTTP_CODE=' + str( _http_code) + ' SERVER_IPPORT=*  IP_SOURCE=* ' +  ' earliest=-1h latest=now'
                                msg_search_splunk = urllib.quote(msg_search_splunk)
                                msg_link_splunk = "https://10.3.65.136:8000/en-US/app/search/search?q=" + msg_search_splunk
                                history_graph = "https://grafana.cnht.vn/d/d3VJnJSMz/ddos-sla-site?var-http=" + str( _http_code) + "&var-domain=" + str(_domain)

                                svr_text = svr_text + " <a href='" + msg_link_splunk + " '>" +  _domain + " </a>" + "\n"
                                svr_text = svr_text \
                                        + " |  SERVER_PORT   |   count  |  percent  | \n"
                                for _svr in _get_svr_list:
                                    svr_text = svr_text \
                                        + " |" + _svr['SERVER_IPPORT'] + " | " + _svr['count'] + " | " + str(int(round(float(_svr['percent'])))) + "%" + " | \n"
                            manager = each_domain_manager

                    if int(_count_each_domain) >= influx_minimum:
                        metric_name=MEASUREMENT + ',' + 'domain=' + str(_domain) + ',' +  'http=' + str(_http_code) + ',' +  'manager=' + str(manager) +  ' value=' + str(_count_each_domain)
                        print "influx_metric is", metric_name
                        influxdb_insert(metric_name)

                    if int(_count_each_domain) >= count_log_warn:
                        domains = domains + "|" + _domain + " |  " +  str(_count_each_domain) + "|   " + str(_percent) + "%\n"
                        #domains = domains + "|" +  _domain +  " |  " +  str(_count_each_domain) + "|   " + str(_percent) + "%  |" + " <a href=\"" + msg_link_splunk + "\"> Trouble  </a>" + " <a href=\"" + history_graph + "\"> History </a> \n"
                print "svr_text is : ", svr_text
                print  "link is", msg_link_splunk

                msg = "<strong>Domain:</strong> {} \n" \
                            "    - Error: {}\n" \
                            "    - Count: {} / {}\n" \
                            "{}\n" \
                            "{}\n" \
                            "<pre><code> \n" \
                            "{}\n" \
                            "</code></pre>". format(DOMAIN,_http_code,_count,time_get_log,domains,str(svr_text),logs)
                sql_insert(session_id, DOMAIN, alert_type, _count, raw_log)
                if _alert_time == False:
                    print "API Alert: no value setup on splunk or DB, sysadmin need setup now!"
                elif alert_yes == True:
                    print "API Alert: API update status & notify"
                    if have_alert:
                        print  "OK:  Alert is", have_alert
                        print "Send notify"
                        print msg
#                        print chat_id
                        manager_array = list(dict.fromkeys(manager_array))
                        for _manager in manager_array:
                            print "each_domain: with manager {}" . format(_manager)
                            chat_id = call_api_alert_manager(_manager)
                            alert.send_telegram(msg, chat_id)
                    else:
                        print "Warn:  Alert is", alert
                else:
                    print "API Alert: sleep to {}m, don't alert anything!" . format(time_alert_to_live)

        if have_result == False:
            print "Nothing to DB, everything is ok on code: ", _http_code


if __name__ == "__main__":
    session_id = uuid.uuid4()

    DOMAIN_LIST = ["*vivavietnam.vn", "*vivavietnam.vn", "*aiservice.vn", "*pega.vn", "*deqik.com", "*socialindex.vn", "*surfcountor.com","*mobilead.vn", "*weball.vn", "*viewplus.vn", "*kinglive.vn", "*lavadin.com", "*lotus.vn", "*admicro.vn", "*cnnd.vn","*soha.vn", "*cafef.vn", "*cafebiz.vn", "*autopro.com.vn", "*genk.vn", "*gamek.vn", "*kenh14.vn", "*afamily.vn", "*vtv.vn", "*giadinh.net.vn", "*nld.com.vn", "*vneconomy.vn", "*ttvn.vn", "*vce.vn","*maoristudio.net", "*tuoitre.vn", "*vcmedia.vn", "*bizflycloud.vn", "*ewings.vn","*sohagame.vn","*sohatv.vn","*linkhay.vn", "*kinghub.vn", "*vietid.net","*sohacorp.vn", "*viewplus.vn","*nanda.vn", "*lotuscdn.vn", "*linkhay.com", "*mediacdn.vn", "*hot14.vn", "*toquoc.vn", "*nhipsongkinhte.vn", "*danviet.vn", "*cnht.vn", "*nhadat.vn", "*vccloud.vn","*suckhoehangngay.vn", "*vietnammoi.vn", "*vietnambiz.vn", "*phunuvietnam.com.vn","*phunuvietnam.vn", "*etime.com.vn","*doanhnghieptiepthi.vn", "*trangtraiviet.vn", "*langcuoi.vn","*phapluatxahoi.vn", "*afemmelist.vn", "*cinet.vn", "*ictvietnam.vn", "*theothaovanhoa.vn", "*ltus.me", "*gov.vn", "*omgnature.com", "*vccorp.vn", "*wow-media.vn", "*wowholiday.vn", "*marketing-vn.com", "*dienanhtrongtamtay.com", "*iztrip.vn", "*wingstudio.vn", "*lapvip.vn", "*bipbip.vn", "*sohaplay.vn", "*ming.vn", "*socnhi.com.vn", "*eat.vn", "*trunkpkg.com", "*amcdn.vn", "*socnhi.com", "*welax.vn", "*dthp.vn", "*bff.vn", "*bikipmuathi.vn", "*connectg.info", "*sohacoin.vn", "*gocnhin.com", "*mysoha.vn", "*ttvnol.com", "*bizfly.vn", "*ovem.vn"]

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(get_splunk_log_from_domain,session_id, DOMAIN): DOMAIN for DOMAIN in DOMAIN_LIST}
        for future in as_completed(future_to_domain):
            each_domain = future_to_domain[future]
            try:
                print future.result()
            except Exception as exc:
                print ('%r generated an exception: %s' %(each_domain, exc))

