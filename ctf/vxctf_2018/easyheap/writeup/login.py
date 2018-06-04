import string
for i in range(97):
    v = [0x41]*11
    v[1-1] = i
    v[2-1] = 97-v[0]
    v[3-1] =166-v[1]
    v[4-1]=169-v[2]
    v[5-1]=129-v[3]
    v[6-1]=142-v[4]
    v[7-1]=174-v[5]
    v[8-1]=207-v[6]
    v[9-1]=150-v[7]
    v[10-1]=104-v[8]
    if all([chr(x) in string.printable for x in v]):
        print ''.join([chr(x) for x in v])
        break
    
