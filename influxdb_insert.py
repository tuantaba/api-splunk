
#!/usr/bin/python
from influxdb import InfluxDBClient


#InfluxDB
client = InfluxDBClient(influx_url, influx_port, influx_user, influx_pass, influx_db)



def influxdb_insert(metric):
    result = client.write(metric, {'db':influx_db},204, protocol='line')
        #    if result.status_code != 204:
        #        print >> sys.stderr, result.text
    return result



