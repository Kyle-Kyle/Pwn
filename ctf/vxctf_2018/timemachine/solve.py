import angr

import logging
logging.getLogger('angr.manager').setLevel(logging.DEBUG)

proj = angr.Project('./timemachine')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x00000000004007F2)
#print simgr.found[0].posix.dumps(0)
