import ipaddress
from ciscoconfparse import CiscoConfParse
import re
from ipaddress import IPv4Address, IPv4Network
import socket
import sys


def read_config_cisco(filename: str):
    rules = {}
    parse = CiscoConfParse(filename, syntax='ios')
    obj_network = parse.find_objects_w_child(parentspec=r"^object network", childspec=r"host|subnet|range")

    for obj in obj_network:
        net_type = obj.re_match_iter_typed(r'(host|range|subnet)\s(\d+\.\d+\.\d+\.\d+(?:\s\d+\.\d+\.\d+\.\d+)*)',
                                      result_type=str, group=1, default='')
        net_value = obj.re_match_iter_typed(r'(host|range|subnet)\s(\d+\.\d+\.\d+\.\d+(?:\s\d+\.\d+\.\d+\.\d+)*)',
                                      result_type=str, group=2, default='')

        name = re.match(r'object network (.+)', obj.text)[1]
        if net_type == 'host':
            rules[name] = net_value
        elif net_type == 'range':
            rules[name] = net_value.replace(' ', '-')
        elif net_type == 'subnet':
            rules[name] = str(IPv4Network(net_value.replace(' ', '/')))
        else:
            pass
    return rules
    # for rule, val in rules.items():
    #     print(rule, val)


def set_nat_rules(filename: str, rules: dict):
    with open(filename, 'r') as f:
        for line in f:
            m = re.match(r'\d+\s\((\S+)\)\sto\s\((\S+)\)\s\S+\s(\S+)\s([\S\.\-]+)\s([\S\.\-]+)', line.strip())
            cmd = f"nft add rule ip nat POSTROUTING ip saddr {{ {rules[m[4]]} }} counter snat to {rules[m[5]]} comment {m[4]}"
            print(cmd)
            if m[3] == 'static':
                cmd = f"nft add rule ip nat PREROUTING ip daddr {{ {rules[m[5]]} }} counter dnat to {rules[m[4]]} comment {m[4]}"
                print(cmd)
    print('\r-------------------------------------------\r')


def parse_acl(filename: str):
    rules = {}
    nft_rules = {}
    asa_rules = {}
    with open(filename, 'r') as f:
        for line in f:
            match = re.match(r'\s*access-list (?P<acl>\S+) line (?P<line>\d+) (?P<type>\w+).+', line.strip())
            if match:
                if match['type'] == 'remark':
                    pass
                elif match['type'] == 'advanced':
                    m = re.match(
                        r'\s*access-list (?P<acl>\S+) '
                        r'line (?P<line>\d+) '
                        r'(?P<type>\w+) '
                        r'(?P<action>\w+) '
                        r'(?P<proto>\w+) '
                        r'(?P<src>any(?: eq \S+|range \S+ \S+)*|host \d+\.\d+\.\d+\.\d+(?: eq \S+| range \S+ \S+)*|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|ifc \S+ (?:any(?: eq \S+| range \S+ \S+)*|host \d+\.\d+\.\d+\.\d+(?: eq \S+| range \S+ \S+)*|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)) '
                        r'(?P<dst>any(?: eq \S+|range \S+ \S+)*|host \d+\.\d+\.\d+\.\d+(?: eq \S+| range \S+ \S+)*|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+|ifc \S+ (?:any(?: eq \S+| range \S+ \S+)*|host \d+\.\d+\.\d+\.\d+(?: eq \S+| range \S+ \S+)*|\d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+)) '
                        r'rule-id (?P<rule_id>\S+)',
                        line)
                    if m:
                        rules.setdefault(m['rule_id'], [])
                        rules[m['rule_id']].append({
                            'action': m['action'],
                            'proto': m['proto'],
                            'src': m['src'],
                            'dst': m['dst']
                        })
                        # print(m['line'], m['rule_id'], m['proto'], '['+m['src']+']', '['+m['dst']+']')
                        pass
                    elif not re.search(r'object-group', line.strip()):
                        print('ERROR: ', line.strip())
                else:
                    print('ERROR: Неизвестный type', match['type'])
                # if int(match['line']) > 3649:
                #     break
        for rule_id in rules:
            nft_rules.setdefault(rule_id, [])
            asa_rules.setdefault(rule_id, [])
            saddr = set()
            daddr = set()
            ports = set()
            proto = set()
            cmd = 'nft add rule ip filter DOCKER-USER'
            cmd_asa = ''
            for record in rules[rule_id]:
                proto.add(record['proto'])

                if re.search(r'any', record['src']):
                    pass
                elif re.match(r'.*host (\S+)', record['src']):
                    ip = re.match(r'.*host (\S+)', record['src'])[1]
                    saddr.add(ip)
                elif re.match(r'(?:\S+ \S+ )*(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', record['src']):
                    m = re.match(r'(?:\S+ \S+ )*(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', record['src'])
                    ip = ipaddress.IPv4Network(f'{m[1]}/{m[2]}')
                    saddr.add(str(ip))
                elif re.match(r'eq \S+|range \S+ \S+', record['src']):
                    print('ERROR: Добавить обработку src ports', rule_id)

                if re.match(r'.*any', record['dst']):
                    pass
                elif re.match(r'.*host (\S+)', record['dst']):
                    ip = re.match(r'.*host (\S+)', record['dst'])[1]
                    daddr.add(ip)
                elif re.match(r'(?:\S+ \S+ )*(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', record['dst']):
                    m = re.match(r'(?:\S+ \S+ )*(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)', record['dst'])
                    ip = ipaddress.IPv4Network(f'{m[1]}/{m[2]}')
                    daddr.add(str(ip))
                if re.search(r'eq \S+|range \S+ \S+', record['dst']):
                    # print('ERROR: Добавить обработку dst ports', rule_id)
                    p = re.search(r'eq (\S+)', record['dst'])
                    if p:
                        port = p[1]
                    else:
                        p = re.search(r'range (\d+) (\d+)', record['dst'])
                        if p:
                            port = f'{p[1]}-{p[2]}'
                        p = re.search(r'range ([a-zA-Z\-]+) ([a-zA-Z\-]+)', record['dst'])
                        if p:
                            # print(p[1], p[2])
                            # print(record['proto'])
                            p1 = socket.getservbyname(p[1], record['proto'])
                            p2 = socket.getservbyname(p[2], record['proto'])
                            port = f'{p1}-{p2}'
                           #print('ERROR: range для текста', p1, p2)
                    ports.add(port)
            if saddr:
                cmd += ' ip saddr { ' + ', '.join(sorted(saddr)) + ' }'
            if daddr:
                cmd += ' ip daddr { ' + ', '.join(sorted(daddr)) + ' }'

            if 'ip' not in proto:
                if len(proto) == 1:
                    cmd += ' ' + record['proto']
                else:
                    cmd += ' meta l4proto { ' + ', '.join(sorted(proto)) + ' }'
            if ports:
                if len(proto) == 1:
                    cmd += ' dport { ' + ', '.join(sorted(ports)) + ' }'
                else:
                    cmd += ' th dport { ' + ', '.join(sorted(ports)) + ' }'
            cmd += ' counter'
            if record['action'] == 'permit' or record['action'] == 'trust':
                cmd += ' accept'
            elif record['action'] == 'deny':
                cmd += ' drop'
            cmd += ' comment rule-id_' + rule_id
            nft_rules[rule_id] = cmd
        for l in nft_rules:
            print(nft_rules[l])


def main():

    rules = read_config_cisco("asa\\fp_sh_run.log")
    pass
#    set_nat_rules("224\\nat_rules", rules)
#    parse_acl("224\\ftd_access_list")
    parse_acl("asa\\fp_sh_access-list.log")


if __name__ == '__main__':
    main()
