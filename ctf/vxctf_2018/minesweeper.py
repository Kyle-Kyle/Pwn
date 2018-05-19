#vxctf{r4nd0m_w17h_f1x3d_5e3d_5ucks_b4d1y}
from pwn import *
import claripy
import time
#context.log_level = 'DEBUG'
# init table
class Mine():
    def __init__(self):
        self.remain = [0]*9
        self.r = remote('35.194.142.188', 8002)
        self.interests  = set([])
    def parse_table(self, raw_table):
        raw_table = raw_table.splitlines()
        raw_table = [ x for x in raw_table if x ][2:]
        raw_table = [ x.split('| ', 1)[1] for x in raw_table]
        for row in range(36):
            new_row = [raw_table[row][i:i+4] for i in range(0, len(raw_table[row]), 4)]
            if len(self.table[row]):
                for j in range(36):
                    if self.table[row][j] != new_row[j] and '[' in new_row[j]:
                        num = int(new_row[j][1:-1])
                        self.solver.add(self.mines[row][j] == 0)
                        near = []
                        for a in [-1, 0, 1]:
                            for b in [-1, 0, 1]:
                                if row+a <0 or j+b <0 or row+a>8 or j+b>8:
                                    continue
                                if a == 0 and b ==0:
                                    continue
                                near.append((row+a, j+b))
                                self.interests.add((row+a, j+b))
                        near = ['self.mines[{}][{}]'.format(i, j) for (i, j) in near]
                        exp = eval('+'.join(near)+'=={}'.format(num))
                        self.solver.add(exp)

            self.table[row] = new_row
    def parse_remain(self):
        self.r.recvuntil('\n')
        nums = self.r.recvuntil('\n').strip().split(' ')
        nums = [x for x in nums if x][1:]
        for i in range(9):
            self.remain[i] = nums[i]
    def parse(self, result):
        results = result.split('Mobs remaining:')
        self.parse_table(results[0])
    def show_table(self):
        line = '    '
        for col in range(36):
            line += ' %2d '%col
        print line
        for row in range(36):
            line = ' %2d '%row
            for col in range(36):
                line += self.table[row][col]
            print line
    def try_solve(self):
        for row, col in self.interests:
            ans = self.solver.eval(self.mines[row][col], 2)
            if len(ans) == 2:
                continue
            print row, col, ans[0]

    def click(self, inp):
        self.r.sendline(inp)
    def start(self):
        self.mines = {}
        self.table = {}
        self.remain = {}
        self.solver = claripy.Solver()
        for i in range(36):
            self.mines[i] = {}
            self.table[i] = {}
            for j in range(36):
                name = 'var_{}_{}'.format(i, j)
                self.mines[i][j] = claripy.BVS(name, 6)
                self.solver.add(self.mines[i][j]>=0)
                self.solver.add(self.mines[i][j]<10)
        self.r.sendline('1')

# init

inps = []
for i in range(36):
    for j in range(36):
        inps.append((i,j))
inps.remove((0,0))

table = {0: [1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1], 1: [0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1], 2: [0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0], 3: [0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1], 4: [0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1], 5: [1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1], 6: [0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1], 7: [1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0], 8: [1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1], 9: [1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1], 10: [1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1], 11: [1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0], 12: [1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0], 13: [0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0], 14: [1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0], 15: [0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1], 16: [1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1], 17: [1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1], 18: [1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0], 19: [1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1], 20: [1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1], 21: [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1], 22: [1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1], 23: [1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1], 24: [0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1], 25: [1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0], 26: [1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1], 27: [1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1], 28: [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1], 29: [0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1], 30: [1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1], 31: [1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0], 32: [1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1], 33: [1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0], 34: [0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1], 35: [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1]}
for i in range(36):
    for j in range(36):
        if type(table[i][j]) == int:
            try:
                inps.remove((i,j))
            except Exception:
                pass
table[0][0] = 1
for (i, j) in inps:

    r = remote('35.194.142.188', 8002)
    r.recvuntil('RESPONSE > ')
    r.sendline('1')
    result = r.recvuntil('RESPONSE > ')
    inp = '0 0'
    r.sendline(inp)
    result = r.recvuntil('RESPONSE > ')

    #time.sleep(1)
    #print r.communicate()
    inp = '{} {}'.format(i, j)
    print inp
    #inp = raw_input('which to open:')
    #m.try_solve()
    r.sendline(inp)
    result = r.recvuntil('RESPONSE > ')
    r.close()

    if 'Select a grid to open' in result:
        print 'good'
        table[i][j] = 1
        print table
    elif 'Game over!' in result:
        print 'bad'
        table[i][j] = 0
        print table

r = remote('35.194.142.188', 8002)
r.recvuntil('RESPONSE > ')
r.sendline('1')
result = r.recvuntil('RESPONSE > ')
for i in table.keys():
    for j in range(36):
        if table[i][j] == 0:
            continue
        if i==35 and j > 15:
            continue
        inp = '{} {}'.format(i, j)
        r.sendline(inp)
        result = r.recvuntil('RESPONSE > ')
        print result
r.interactive()


