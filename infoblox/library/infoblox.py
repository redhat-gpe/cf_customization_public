#!/usr/bin/python

DOCUMENTATION = '''
module: infoblox
version_added: "1.0"
short_description: Manage infoblox opeartion by useing rest api .   
'''
EXAMPLES = '''
#Adding host record to infoblox 
- hosts: "{{ hosts }}"
  user: root
  serial: 1
  gather_facts: False
  vars_prompt:
    - name: "infoblox_username"
      prompt: "Infoblox Username"
      private: no
    - name: "infoblox_password"
      prompt: "Infoblox Password"
      private: yes
  tasks:
    # --------------------------------------------------------------------
    # 1. Querying the hostrecords from Infoblox REST api.
    # --------------------------------------------------------------------
    - name: "Querying the hostrecords from Infoblox"
      local_action: >
        infoblox
        fqdn="{{ inventory_hostname }}"
        address="{{ ipaddress }}"
        iba_ipaddr="{{ infoblox_gridmaster }}"
        iba_user="{{ infoblox_username }}"
        iba_password="{{ infoblox_password }}"
        iba_wapi_version="{{ infoblox_version }}"
        iba_dns_view="{{ infoblox_view }}"
        iba_network_view="{{ infoblox_network_view }}"
        iba_verify_ssl="False"
        state="add"
      ignore_errors: yes

# Deleteing host record  from infoblox 
- hosts: "{{ hosts }}"
  user: root
  serial: 1
  gather_facts: False
  vars_prompt:
    - name: "infoblox_username"
      prompt: "Infoblox Username"
      private: no
    - name: "infoblox_password"
      prompt: "Infoblox Password"
      private: yes
  tasks:
    # --------------------------------------------------------------------
    # 1. Deleteing hostrecord from infoblox bu useing  REST api
    # --------------------------------------------------------------------
    - name: "Deleteing hostrecords from Infoblox"
      local_action: >
        infobloxtapan
        fqdn="{{ inventory_hostname }}"
        iba_ipaddr="{{ infoblox_gridmaster }}"
        iba_user="{{ infoblox_username }}"
        iba_password="{{ infoblox_password }}"
        iba_wapi_version="{{ infoblox_version }}"
        iba_dns_view="{{ infoblox_view }}"
        iba_network_view="{{ infoblox_network_view }}"
        iba_verify_ssl="False"
        state="delete"
      ignore_errors: yes


Lastly 
 
You need to pass  below default parameter  from your playbook . 
 
infoblox_gridmaster: <infoblox servername>
infoblox_username:
infoblox_version: 1.4.2 this version number is very important
infoblox_view: <view>
infoblox_network_view: default
infoblox_ssl: False
infoblox_password:


'''

import re
import requests
import json
import os
import urllib3
urllib3.disable_warnings()
class InfobloxNotFoundException(Exception):
    pass

class InfobloxNoIPavailableException(Exception):
    pass

class InfobloxGeneralException(Exception):
    pass

class InfobloxBadInputParameter(Exception):
    pass

class Infoblox(object):
    """ Implements the following subset of Infoblox IPAM API via REST API
       
    """

    def __init__(self, iba_ipaddr, iba_user, iba_password, iba_wapi_version, iba_dns_view, iba_network_view, iba_verify_ssl=True):
        '''Class initialization method
	:param iba_ipaddr: IBA IP address of management interface
	:param iba_user: IBA user name
	:param iba_password: IBA user password
	:param iba_wapi_version: IBA WAPI version (example: 1.0)
	:param iba_dns_view: IBA default view
	:param iba_network_view: IBA default network view
        :param iba_verify_ssl: IBA SSL certificate validation (example: False)
        '''
	self.iba_host = iba_ipaddr
	self.iba_user = iba_user
	self.iba_password = iba_password
	self.iba_wapi_version = iba_wapi_version
	self.iba_dns_view = iba_dns_view
	self.iba_network_view = iba_network_view
        self.iba_verify_ssl = iba_verify_ssl
    
    def get_next_available_ips(self,network,number='10'):
	""" Implements IBA next_available_ip REST API call
	Returns IP v4 address
	:param network: network in CIDR format
	"""
	rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/network?network=' + network + '&network_view=' + self.iba_network_view
	try:
	    r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
	    r_json = r.json()
	    if r.status_code == 200:
		if len(r_json) > 0:
		    net_ref = r_json[0]['_ref']
                    #Changed the num 1 to 10 for gettting 10 free ips 
		    rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/' + net_ref + '?_function=next_available_ip&num='+number
		    r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
		    r_json = r.json()
		    if r.status_code == 200 :
			ip_v4 = r_json['ips']
			return ip_v4
		    else:
			if 'text' in r_json:
			    if 'code' in r_json and r_json['code'] == 'Client.Ibap.Data':
				raise InfobloxNoIPavailableException(r_json['text'])
			    else:
				raise InfobloxGeneralException(r_json['text'])
			else:
			    r.raise_for_status()
		else:
		    raise InfobloxNotFoundException("No requested network found: " + network)
	    else:
		if 'text' in r_json:
		    raise InfobloxGeneralException(r_json['text'])
		else:
		    r.raise_for_status()
	except ValueError:
	    raise Exception(r)
	except Exception:
	    raise    
    def get_host_by_search(self, fqdn):
	""" Implements IBA REST API call to retrieve host records by fqdn regexp filter
	Returns array of host names in FQDN matched to given regexp filter
	:param fqdn: hostname in FQDN or FQDN regexp filter
	"""
	rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/record:host?name~=' + fqdn + '&view=' + self.iba_dns_view
	hosts = []
	try:
            #print rest_url
            #print self.iba_user
            #print self.iba_verify_ssl
           
	    #r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl)
	    r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
	    r_json = r.json()
	    if r.status_code == 200:
		if len(r_json) > 0:
		    for host in r_json:
			hosts.append(host['name'])
		    return hosts
		else:
		    raise InfobloxNotFoundException("No hosts found for regexp filter: " + fqdn)
	    else:
		if 'text' in r_json:
		    raise InfobloxGeneralException(r_json['text'])
		else:
		    r.raise_for_status()
	except ValueError:
	    raise Exception(r)
	except Exception:
	    raise
    def get_next_available_ip(self,network):
        """ Implements IBA next_available_ip REST API call
        Returns IP v4 address
        :param network: network in CIDR format
        """
        rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/network?network=' + network + '&network_view=' + self.iba_network_view
        try:
            r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
            r_json = r.json()
            if r.status_code == 200:
                if len(r_json) > 0:
                    net_ref = r_json[0]['_ref']
                    #Changed the num 1 to 10 for gettting 10 free ips 
                    rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/' + net_ref + '?_function=next_available_ip&num=5'
                    r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
                    r_json = r.json()
                    if r.status_code == 200:
                        ip_v4 = r_json['ips']
                        for i in range(len(ip_v4)): 
                           ip_v4 = r_json['ips'][i]
                           response = os.system("ping -c 1 -w2 " + ip_v4 + " > /dev/null 2>&1")
                           if response != 0:
                              #print ip_v4,'free and down'   
                              return ip_v4
                    else:
                        if 'text' in r_json:
                            if 'code' in r_json and r_json['code'] == 'Client.Ibap.Data':
                                raise InfobloxNoIPavailableException(r_json['text'])
                            else:
                                raise InfobloxGeneralException(r_json['text'])
                        else:
                            r.raise_for_status()
                else:
                    raise InfobloxNotFoundException("No requested network found: " + network)
            else:
                if 'text' in r_json:
                    raise InfobloxGeneralException(r_json['text'])
                else:
                    r.raise_for_status()
        except ValueError:
            raise Exception(r)
        except Exception:
            raise
    def create_host_record(self, address, fqdn):
	""" Implements IBA REST API call to create IBA host record
	Returns IP v4 address assigned to the host
	:param address: IP v4 address or NET v4 address in CIDR format to get next_available_ip from
	:param fqdn: hostname in FQDN
	"""
	if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$", address):
	    #ipv4addr = 'func:nextavailableip:' + address
	    ipv4addr =  self.get_next_available_ip(address)
            ipv4addr = str(ipv4addr) 
            #print ipv4addr
	else:
	    if re.match("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", address):
		ipv4addr = address
	    else:
		raise InfobloxBadInputParameter('Expected IP or NET address in CIDR format')
        rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/record:host' + '?_return_fields=ipv4addrs'
	payload = '{"ipv4addrs": [{"configure_for_dhcp": false,"ipv4addr": "' + ipv4addr + '"}],"name": "' + fqdn + '","view": "' + self.iba_dns_view + '"}'
	try:
	    #r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=self.iba_verify_ssl, data=payload)
	    r = requests.post(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False, data=payload)
	    r_json = r.json()
	    if r.status_code == 200 or r.status_code == 201:
	    	return r_json['ipv4addrs'][0]['ipv4addr']
	    else:
		if 'text' in r_json:
		    raise InfobloxGeneralException(r_json['text'])
		else:
		    r.raise_for_status()
	except ValueError:
	    raise Exception(r)
	except Exception:
	    raise
        return ipv4addr
    def delete_host_record(self, fqdn):
	""" Implements IBA REST API call to delete IBA host record
	:param fqdn: hostname in FQDN
	"""
	rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/record:host?name=' + fqdn + '&view=' + self.iba_dns_view
	try:
	    r = requests.get(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
	    r_json = r.json()
	    if r.status_code == 200:
		if len(r_json) > 0:
		    host_ref = r_json[0]['_ref']
		    if host_ref and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == fqdn:
			rest_url = 'https://' + self.iba_host + '/wapi/v' + self.iba_wapi_version + '/' + host_ref
			r = requests.delete(url=rest_url, auth=(self.iba_user, self.iba_password), verify=False)
			if r.status_code == 200:
			    return
			else:
			    if 'text' in r_json:
				raise InfobloxGeneralException(r_json['text'])
			    else:
				r.raise_for_status()
		    else:
			raise InfobloxGeneralException("Received unexpected host reference: " + host_ref)
		else:
		    raise InfobloxNotFoundException("No requested host found: " + fqdn)
	    else:
		if 'text' in r_json:
		    raise InfobloxGeneralException(r_json['text'])
		else:
		    r.raise_for_status()
	except ValueError:
	    raise Exception(r)
	except Exception:
	    raise

def main():
    module = AnsibleModule(
        argument_spec = dict(
	    state = dict(required=True),
            iba_user = dict(required=True),
	    iba_ipaddr = dict(required=True),
            iba_password = dict(required=True),
            iba_wapi_version = dict(required=True),
            iba_dns_view = dict(required=True),
            iba_network_view = dict(required=True),
            iba_verify_ssl = dict(required=True),
            fqdn = dict(required=True),
            address = dict(required=False)
        )
    )
    #iba_network = dict(required=True),

    state = module.params['state']
    fqdn = module.params['fqdn']
    address = module.params['address']
    infbl = Infoblox(module.params['iba_ipaddr'], module.params['iba_user'], module.params['iba_password'], module.params['iba_wapi_version'], module.params['iba_dns_view'], module.params['iba_network_view'], module.params['iba_verify_ssl']);
    if state == 'absent':
        ipaddr = infbl.create_host_record(address,fqdn)
        module.exit_json(changed=True, msg="IP is '%s'" % ipaddr, ip_addr='%s' % ipaddr)
    elif state == 'present':
        infbl.delete_host_record(fqdn)
        module.exit_json(changed=True, msg="Host '%s' deleted." % fqdn)
    else:
        module.fail_json(msg="The state must be 'absent' or 'present' but instead we found '%s'" % (state))

# import module snippets
from ansible.module_utils.basic import *
main()
