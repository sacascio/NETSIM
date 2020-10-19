import json
import sys
import getopt
from ciscoconfparse import CiscoConfParse
import re
from netaddr import *
import requests

def get_inner_to_outer_encap():

    data = {}

    # Services
    for i in 11,12,13,14:
        data[i] = 141

    # UAC
    for i in 17,18:
        data[i] = 142

    # CTL
    for i in 27,28,29,30:
        data[i] = 144

    # Res
    for i in 45,46:
        data[i] = 147

    return data

def get_vrf_to_encap_fw(dc):
    data = {}

    vrf = []
    vrf.append(['SVC-COM-' + dc.upper() + '-GIS',11])
    vrf.append(['SVC-ITC-' + dc.upper() + '-GIS',12])
    vrf.append(['SVC-BSC-' + dc.upper() + '-GIS',13])
    vrf.append(['SVC-TFR-' + dc.upper() + '-GIS',14])
    vrf.append(['UAC-ENT-' + dc.upper() + '-GIS',17])
    vrf.append(['UAC-HRZ-' + dc.upper() + '-GIS',18])
    vrf.append(['CTL-PA1-' + dc.upper() + '-GIS',27])
    vrf.append(['CTL-PA2-' + dc.upper() + '-GIS',28])
    vrf.append(['CTL-PTM-' + dc.upper() + '-GIS',29])
    vrf.append(['CTL-PTM-DMZ' + dc.upper() + '-GIS',30])
    vrf.append(['RES-DST' + dc.upper() + '-GIS',45])
    vrf.append(['RES-MMP' + dc.upper() + '-GIS',46])

    for i in vrf:
        vrfname = i[0]
        inner_encap = i[1]
        data[vrfname] = {}
        data[vrfname][inner_encap] = {}

        if bool(re.search('RES-MMP',vrfname,re.IGNORECASE)):
            data[vrfname][inner_encap] = dc.lower() + 'gisnwa1pfw2a'
        else:
            data[vrfname][inner_encap] = dc.lower() + 'gisnwa1pfw1a'

    return data


def load_rd():

    return rd

def load_fw_ips():

    return fw_ips


def usage():
    print ("Usage: " + sys.argv[ 0] + " -d|--dc <dc1 or dc2> -v <VRF as defined on N7K -f FW name")
    sys.exit(1)

def get_inner_config(filename,vrf,inner_encap,basedir,bgpid,fw):
    data = []
    vrfmember = 'vrf ' + vrf
    parse = CiscoConfParse(basedir + filename)

    # SVI
    for obj in parse.find_objects("interface Vlan" + str(inner_encap)):
        svi = obj.text
        data.append(svi)
        if obj.hash_children != 0:
            for c in obj.children:
                if bool(re.search('ip address',c.text)):
                    ip = c.text
                    ip = ip.replace("ip address ","")
                    ip = ip.replace("/30","")
                    ip = ip.strip()
                data.append(c.text)
    # BGP
    for obj in parse.find_objects("router bgp " + str(bgpid)):
        rtr_bgp =  obj.text
        data.append(rtr_bgp)
        if obj.hash_children != 0:
            for c in obj.children:
                c.text = c.text.strip()
                if vrfmember == c.text:
                    data.append(vrfmember)
                    for bgpdata in c.children:
                        data.append(bgpdata.text)
                        if bgpdata.hash_children != 0:
                            for subdata in bgpdata.children:
                                data.append(subdata.text)
                                if subdata.hash_children != 0:
                                    for subdata2 in subdata.children:
                                        data.append(subdata2.text)

    # Trunk Link
    data.append("interface Ethernet2/10")
    data.append(" description to " + fw)
    data.append(" switchport")
    data.append(" switchport mode trunk")
    data.append(" switchport trunk allowed vlan add " + str(inner_encap))
    data.append(" no shutdown")

    # Create L2 VLAN
    data.append("vlan " + str(inner_encap))
    return (ip,data)

def get_outer_config(filename,vrf,outer_encap,basedir,bgpid,fw):
    data = []
    vrfmember = 'vrf ' + vrf
    parse = CiscoConfParse(basedir + filename)

    # SVI
    for obj in parse.find_objects("interface Vlan" + str(outer_encap)):
        svi = obj.text
        data.append(svi)
        if obj.hash_children != 0:
            for c in obj.children:
                if bool(re.search('ip address',c.text)):
                    ip = c.text
                    ip = ip.replace("ip address ","")
                    ip = ip.replace("/30","")
                    ip = ip.strip()
                data.append(c.text)
    # BGP
    bgp_details = parse.find_all_children("^router bgp")
    for d in bgp_details:
        data.append(d)

    # Trunk Link
    data.append("interface Ethernet2/10")
    data.append(" switchport")
    data.append(" switchport mode trunk")
    data.append(" switchport trunk allowed vlan add " + str(outer_encap))
    data.append(" no shutdown")

    return (ip,data)

def push_to_n7k(ip,commands):
    content_type = "json"
    HTTPS_SERVER_PORT = "8080"
    to_delete = []
    commands[0].append("! SAL")
    for element, c in enumerate(commands[0]):
        if c == '' or bool(re.search('!', c)):
            to_delete.append(c)
        else:
            c = c.lstrip()

    for d in to_delete:
        commands[0].remove(d)

    commands[0] = " ; ".join(map(str, commands[0]))

    requests.packages.urllib3.disable_warnings()

    if commands[0].endswith(" ; "):
        commands[0] = commands[0][:-3]

    payload = {
        "ins_api": {
            "version": "1.2",
            "type": "cli_conf",
            "chunk": "0",  # do not chunk results
            "sid": "0",
            "input": commands,
            "output_format": "json"
        }
    }

    headers = {'content-type': 'application/%s' % content_type}
    response = requests.post("https://%s:%s/ins" % (ip, HTTPS_SERVER_PORT),
                             auth=('admin', 'admin'),
                             headers=headers,
                             data=json.dumps(payload),
                             verify=False,  # disable SSH certificate verification
                             timeout=60)

    if response.status_code == 200:
        allcmds = commands.split(" ; ")
        # verify result
        data = response.json()
        # print (json.dumps(data))
        if isinstance(data['ins_api']['outputs']['output'], dict):
            if int(data['ins_api']['outputs']['output']['code']) != 200:
                data['ins_api']['outputs']['output']['msg'] = data['ins_api']['outputs']['output']['msg'].rstrip()
                print("ERROR: %s, %s.  Command is: %s" % ('msg', data['ins_api']['outputs']['output']['msg'], commands))
            else:
                if 'body' in data['ins_api']['outputs']['output'] and len(
                        data['ins_api']['outputs']['output']['body']) > 0:
                    print(data['ins_api']['outputs']['output']['body'])
        else:
            for d in data['ins_api']['outputs']['output']:
                for k in d.keys():
                    if int(d['code']) != 200:
                        cmd_number = data['ins_api']['outputs']['output'].index(d)
                        if k != 'code':
                            if not isinstance(d[k], dict):
                                d[k] = d[k].rstrip()
                                print("ERROR: %s, %s.  Command is: %s" % (k, d[k], allcmds[cmd_number]))
                if 'body' in d and len(d['body']) > 0:
                    print(d['body'])

    else:
        msg = "call to %s failed, status code %d (%s).  Command is %s." % (ip,
                                                                           response.status_code,
                                                                           response.content.decode("utf-8"),
                                                                           commands
                                                                           )
        print(msg)

    return

def print_fw_config(fwinner,fwouter):

    return config

def add_static_routes(vdcnum,svi_ips,vrf,config,location):
    # inner_config = add_static_routes(vdcnum,outer_svi_ips,vrf,inner_config,'inner')
    cfg_svi_ip = config[vrf][str(vdcnum)]['svi']

    if location == 'inner':
        cfg_svi_ip_plus_1 = IPAddress(cfg_svi_ip)
        cfg_svi_ip_plus_1 = cfg_svi_ip_plus_1 + 1
        config[vrf][str(vdcnum)]['config'][0].append('vrf context ' + vrf)
        for ips in svi_ips:
            ips_less_2 = IPAddress(ips)
            ips_less_2 = ips_less_2 - 2
            config[vrf][str(vdcnum)]['config'][0].append(' ip route ' + str(ips_less_2) + '/30 ' + str(cfg_svi_ip_plus_1))

    if location == 'outer':
        cfg_svi_ip_less_1 = IPAddress(cfg_svi_ip)
        cfg_svi_ip_less_1 = cfg_svi_ip_less_1 - 1
        for ips in svi_ips:
            ips_less_1 = IPAddress(ips)
            ips_less_1 = ips_less_1 - 1
            config[vrf][str(vdcnum)]['config'][0].append('ip route ' + str(ips_less_1) + '/30 ' + str(cfg_svi_ip_less_1))

    return config

def main(argv):
    basedir = "/Users/scascio/GitHub/ACI/SG_PBR/"
    try:
        opts, args = getopt.getopt(argv, "d:v:h", ["dc=","vrf=", "help"])
    except getopt.GetoptError as err:
        print (str(err))
        sys.exit(2)
    else:
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
            if opt in ("-d", "--dc"):
                dc = arg
            if opt in ("-v", "--vrf"):
                vrf = arg
    try:
        dc
    except NameError:
        print ("ERROR: must pass DC1 or DC2")
        sys.exit(1)

    try:
       vrf
    except NameError:
        print ("ERROR: must pass VRF name as defined on the N7K")
        sys.exit(1)

    n7k_ips = {}
    n7k_ips['inner'] = {}
    n7k_ips['outer'] = {}

    n7k_files = {}
    n7k_files['inner'] = {}
    n7k_files['outer'] = {}

    inner_to_outer_encap = get_inner_to_outer_encap()


    if dc.upper() == 'DC2':
        n7k_ips['inner'][1] = '172.21.41.107'
        n7k_ips['inner'][2] = '172.21.41.108'
        n7k_ips['inner'][3] ='172.21.41.109'
        n7k_ips['inner'][4] ='172.21.41.110'

        n7k_ips['outer'][1] = '172.21.41.111'
        n7k_ips['outer'][2] = '172.21.41.112'
        n7k_ips['outer'][3] = '172.21.41.113'
        n7k_ips['outer'][4] ='172.21.41.114'
        n7k_bgp_id_inner = 65512
        n7k_bgp_id_outer = 65510
        vrf_to_encap_to_fw = get_vrf_to_encap_fw('dc2')
    else:
        print ("NO IPs defined for DC1 - exiting")
        sys.exit(9)
        n7k_bgp_id_inner = 65502
        n7k_bgp_id_outer = 65500
        vrf_to_encap_to_fw = get_vrf_to_encap_fw('dc1')

    for x in (1,2,3,4):
        n7k_files['inner'][x] = dc.lower() +  'dcinxc' + str(x) + 'gisinner.log'
        n7k_files['outer'][x] = dc.lower() +  'dcinxc' + str(x) + 'dciouter.log'

    # Build Inner
    # Inner config so far has:
    # 1: inner SVI IP and SVI config
    # 2: BGP config for the VRF
    # 3: Need to add vrf context and static routes
    inner_config = {}
    inner_config[vrf] = {}
    inner_svi_ips = []
    for k, v in vrf_to_encap_to_fw[vrf].items():
        inner_encap = k
        fw = v
    for vdcnum in n7k_files['inner']:
        n7kfile = n7k_files['inner'][vdcnum]
        inner_config[vrf][str(vdcnum)] = {}
        inner_config[vrf][str(vdcnum)]['config'] = []
        (inner_svi_ip,config) = get_inner_config(n7kfile,vrf,inner_encap,basedir,n7k_bgp_id_inner,fw)
        inner_config[vrf][str(vdcnum)]['config'].append(config)
        inner_config[vrf][str(vdcnum)]['svi']  = inner_svi_ip
        inner_svi_ips.append(inner_svi_ip)
    # Build Outer
    # Inner config so far has:
    # 1: inner SVI IP and SVI config
    # 2: BGP config for the VRF
    # 3: Need to add static routes and BGP config
    outer_config = {}
    outer_config[vrf] = {}
    outer_svi_ips = []
    for vdcnum in n7k_files['outer']:
        n7kfile = n7k_files['outer'][vdcnum]
        outer_encap = inner_to_outer_encap[inner_encap]
        outer_config[vrf][str(vdcnum)] = {}
        outer_config[vrf][str(vdcnum)]['config'] = []
        (outer_svi_ip,config) = get_outer_config(n7kfile,vrf,outer_encap,basedir,n7k_bgp_id_outer,fw)
        outer_config[vrf][str(vdcnum)]['config'].append(config)
        outer_config[vrf][str(vdcnum)]['svi'] = outer_svi_ip
        outer_svi_ips.append(outer_svi_ip)

    # Add static routes
    for vdcnum in n7k_files['inner']:
        n7kfile = n7k_files['inner'][vdcnum]
        inner_config = add_static_routes(vdcnum,outer_svi_ips,vrf,inner_config,'inner')
    for vdcnum in n7k_files['outer']:
        n7kfile = n7k_files['outer'][vdcnum]
        outer_config = add_static_routes(vdcnum,inner_svi_ips,vrf,outer_config,'outer')

    #Push to N7K
    for i in n7k_ips['inner']:
        ip = n7k_ips['inner'][i]
        i_config =  inner_config[vrf][str(i)]['config']
        push_to_n7k(ip,i_config)
    #print (json.dumps(inner_config))
    #print (json.dumps(outer_config))


if __name__ == '__main__':
    main(sys.argv[1:])