import angr

import logging
logging.getLogger('angr.sim_mananger').setLevel(logging.DEBUG)

proj = angr.Project('./sftp')
state = proj.factory.entry_state(addr=0x4013F0)
simgr = proj.factory.simgr(state)

simgr.explore(find=0x401531)

print [simgr.found[0].posix.dumps(0)]
