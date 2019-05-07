def generate_mud(policies, device_name):
    import datetime
    import json
    t = datetime.time(1, 2, 3)
    d = datetime.date.today()
    dt = datetime.datetime.combine(d, t)
    # print('dt:', dt)
    mud = {}
    from_device_policy = {'access-lists': 
                            {'access-list':
                                [{'name': 'from-ipv4-' + device_name}]
                            }
                        }
    to_device_policy = {'access-lists':
                            {'access-list':
                                [{'name': 'to-ipv4-' + device_name}]
                            }
                        }
    mud['ietf-mud:mud'] = {'mud-version': 1,
                            'mud-url': 'https//' + device_name + '.com/' + device_name,
                            'last-update': str(dt),
                            'cache-validity': 100,
                            'is-supported': True,
                            'systeminfo': device_name,
                            'from-device-policy': from_device_policy,
                            'to-device-policy': to_device_policy
                        }
    from_ace = []
    from_cnt = 0
    for f in policies['from device policies']:
        ace = {}
        ace['name'] = 'from-ipv4-' + device_name + '-' + str(from_cnt)
        ace['matches'] = {'ietf-mud:mud':
                                    {'controller': "urn:ietf:params:mud:gateway"},
                          'ipv4':
                                    {'protocol': 17 if f.split()[0] == 'udp' else 6,
                                     'ietf-acldns:dst-dnsname': f.split()[2]
                                    },
                          f.split()[0]:
                                    {'destination-port': {'operator': 'eq', 'port': f.split()[1]},
                                     'ietf-mud:direction-initiated' : 'from-device'}
                        }
        ace['actions'] = {'forwarding': 'accept'}
        from_ace.append(ace)
        from_cnt += 1
    
    to_ace = []
    to_cnt = 0
    for t in policies['to device policies']:
        ace = {}
        ace['name'] = 'to-ipv4-' + device_name + '-' + str(to_cnt)
        ace['matches'] = {'ietf-mud:mud':
                                    {'controller': "urn:ietf:params:mud:gateway"},
                          'ipv4':
                                    {'protocol': 17 if t.split()[0] == 'udp' else 6,
                                     'ietf-acldns:dst-dnsname': t.split()[2]
                                    },
                          t.split()[0]:
                                    {'destination-port': {'operator': 'eq', 'port': t.split()[1]},
                                     'ietf-mud:direction-initiated' : 'to-device'}
                        }
        ace['actions'] = {'forwarding': 'accept'}
        to_ace.append(ace)
        to_cnt += 1
    
    mud['ietf-access-control-list:access-lists'] = {'acl':
                                                        [
                                                         {'name': 'from-ipv4-' + device_name,
                                                          'type': 'ipv4-acl-type',
                                                          'aces': {'ace': from_ace}
                                                         },
                                                         {'name': 'to-ipv4-' + device_name,
                                                          'type': 'ipv4-acl-type',
                                                          'aces': {'ace': to_ace}
                                                         }
                                                        ]
                                                    }
    # print(mud)
    with open('output_pkl/' + device_name + '.json', 'w') as fp:
        json.dump(mud, fp, indent=2)
