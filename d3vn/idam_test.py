from hashlib import sha256
from operator import xor
from random import randint
from timeit import default_timer as timer


nodes = 1000
clusters = 2
attribute_vector = '1'* clusters
test_iteration = 20


class ip:
    byte_1 = '00000000'
    byte_2 = '00000000'
    byte_3 = '00000000'
    byte_4 = '00000000'
    def __init__(self, a, b, c, d):
        self.byte_1 = a
        self.byte_2 = b
        self.byte_3 = c
        self.byte_4 = d

def random_binary(l):
    bin =''
    for _ in range(l):
        bin += str(randint(0,1))
    return bin


def generate_IP(n):
    ip_list = []
    for _ in range(n):
        random_ip = ip(random_binary(8) , random_binary(8) , random_binary(8) , random_binary(8))
        ip_list.append((random_ip.byte_1, random_ip.byte_2, random_ip.byte_3, random_ip.byte_4))
    return ip_list


def hashing(ip, cluster):
    start = timer()
    ip_str_encoded = (ip[0]+ip[1]+ip[2]+ip[3]).encode() 
    for _ in range(cluster):
        id = sha256(ip_str_encoded).hexdigest()
    end = timer()
    return end - start # Return the time to hash the i

def idamv1(ip, av, cluster):
    start = timer()
    ip_str_encoded = (ip[0]+ip[1]+ip[2]+ip[3]).encode()
    av = av.encode() 
    info_hash = sha256(ip_str_encoded + av).hexdigest()
    #print(info_hash)
    for cl in range(cluster):
        id = sha256(str(cl).encode()).hexdigest()  # cluster hash represents the first d-bits of the final identifier
        id += hex(xor(int(info_hash, 16), int(id, 16))) # The second part of the idnetifier, Permutation: Rotate left (four bits each) based on the number of cluster.
        #id += info_hash[cl:] + info_hash[:cl] # The second part of the idnetifier, Permutation: Rotate left (four bits each) based on the number of cluster. 
    end = timer()
    return end - start # Return the time to create all required identifiers for all given clusters

def idamv2(ip, av, cluster):
    start = timer()
    ip_str_encoded = (ip[0]+ip[1]+ip[2]+ip[3]).encode()
    av = av.encode() 
    for cl in range(cluster):
        id = sha256(str(cl).encode()).hexdigest() # cluster hash represents the first d-bits of the final identifier
        id += sha256(ip_str_encoded + av + str(cl).encode()).hexdigest() # The second part of the idnetifier is the hash of the node info + its AV + the cluster attribute number 
    end = timer()
    return end - start # Return the time to create all required identifiers for all given clusters



ip_list = generate_IP(nodes)

def idam_test_perform():
    t0, t1, t2 = 0, 0, 0
    for i in range(nodes):
        t0 += hashing(ip_list[i], clusters)
    for i in range(nodes):
        t1 += idamv1(ip_list[i], attribute_vector , clusters)
    for i in range(nodes):
        t2 += idamv2(ip_list[i], attribute_vector, clusters)
    t0 /= nodes
    t1 /= nodes
    t2 /= nodes
    return (t0, t1, t2)

def print_parameters():
    print("[x] Start the IDAM test")
    print("[x] Number of clusters: ",clusters)
    print("[x] Number of nodes: ",nodes)
    

def main():
    print_parameters()
    average_time = {'hashing':0, 'idamv1':0, 'idamv2':0}
    for _ in range(test_iteration):
        t = (idam_test_perform())
        average_time['hashing'] += t[0]
        average_time['idamv1'] += t[1]
        average_time['idamv2'] += t[2]
    average_time['hashing'] /= test_iteration
    average_time['idamv1'] /= test_iteration
    average_time['idamv2'] /= test_iteration

    average_time['hashing'] *= 1000     # Convert from second to ms
    average_time['idamv1'] *= 1000
    average_time['idamv2'] *= 1000

    print("[x] only hashing execution time = ", average_time['hashing'])
    print("[x] idamv1 execution time = ", average_time['idamv1'])
    print("[x] idamv2 execution time = ", average_time['idamv2'])

main()