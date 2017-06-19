#!/usr/bin/env python

"""
POC for subnet calculator
"""

import ipaddress


def how_many_fit(max, quantity, size):
    """
    Find the max number of chunks within a max size
    """
    while 42:
        if quantity != 0 and max > (quantity * size) and max == ((quantity + 1) * size):
            return quantity + 1
        elif quantity == 0:
            return 0
        else:
            quantity -= 1

def find_prefix(to_fit, cidr):
    """
    Find the prefix to fit all IPs
    """
    prefix = int(cidr.split('/')[1])
    start_point = cidr.split('/')[0]
    while True:
        new_cidr = u'%s/%d' % (start_point, prefix +1)
        ips = ipaddress.IPv4Network(new_cidr).num_addresses
        if ips == to_fit:
            return prefix +1
        elif (prefix +1) == 28:
            return
        else:
            prefix += 1

def define_supersubnet(azs, layers, network, prefix, block_ips):
    """
    """
    largest = largest_powered_two
    subnet_max_ips = find_power_two(block_ips / azs)
    subnet_prefix = find_prefix(subnet_max_ips, cidr)
    splits = how_many_fit(largest, azs, subnet_max_ips)
    supersized_prefix = find_prefix(largest, cidr)

    while splits < azs:
        largest *= 2
        supersized_prefix = find_prefix(largest, cidr)
        splits = how_many_fit(largest, azs, subnet_max_ips)

    public_block = ipaddress.IPv4Network(u'%s/%s' % (network, supersized_prefix))
    return public_block


def find_power_two(target):
    for i in range(1, int(target)):
        if (2 ** i >= target):
            return 2 ** (i - 1)


if __name__ == '__main__':

    azs = 3
    layers = 3

    cidr = u'10.201.0.0/20'
    vpc_net = ipaddress.IPv4Network(cidr)
    number_ips = vpc_net.num_addresses - 2

    print "MAX NUM HOSTS", number_ips

    public_ratio = 30.0
    app_ratio = 50.0
    db_ratio = 20.0


    enough_public = False
    enough_app = False
    enough_db = False


    public_ips_num = (number_ips * (public_ratio/100))
    app_ips_num = (number_ips * (app_ratio / 100))
    db_ips_num = (number_ips * (db_ratio / 100))


    if ( public_ips_num / azs ) > (public_ratio):
        enough_public = True

    if ( app_ips_num / azs ) > ( app_ratio):
        enough_app = True

    if ( db_ips_num / azs ) > ( app_ratio):
        enough_db = True

    largest_powered_two = find_power_two(number_ips / azs)
    supersized_prefix = find_prefix(largest_powered_two, cidr)

    public_block = define_supersubnet(azs, layers, vpc_net.network_address, vpc_net._prefixlen, public_ips_num)
    exclude_public = list(vpc_net.address_exclude(public_block))
    if len(exclude_public) == 2:
        app_block = define_supersubnet(
            azs, layers,
            exclude_public[0].network_address,
            vpc_net._prefixlen, app_ips_num
        )
        db_block = define_supersubnet(
            azs, layers,
            exclude_public[1].network_address,
            vpc_net.prefixlen, db_ips_num
        )

    print public_block, app_block, db_block

    public_p2 = find_power_two(public_ips_num / azs)
    public_prefix = find_prefix(public_p2, public_block.with_prefixlen)
    public_subnets = public_block.subnets(new_prefix=public_prefix)

    public_subnets_cidr = []
    for subnet in list(public_subnets):
        public_subnets_cidr.append(subnet.with_prefixlen)

    app_p2 = find_power_two(app_ips_num / azs)
    app_prefix = find_prefix(app_p2, app_block.with_prefixlen)
    app_subnets = app_block.subnets(new_prefix=app_prefix)

    app_subnets_cidr = []
    for subnet in list(app_subnets):
        app_subnets_cidr.append(subnet.with_prefixlen)

    db_p2 = find_power_two(db_ips_num / azs)
    db_prefix = find_prefix(db_p2, db_block.with_prefixlen)
    db_subnets = db_block.subnets(new_prefix=db_prefix)

    db_subnets_cidr = []
    for subnet in list(db_subnets):
        db_subnets_cidr.append(subnet.with_prefixlen)

    print db_subnets_cidr
    print app_subnets_cidr
    print public_subnets_cidr

