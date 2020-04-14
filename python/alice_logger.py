import logging

phases = ['locator', 'scoper', 'rewriter', 'main']
default_lvl = logging.DEBUG

hdlr = logging.FileHandler('out.log',mode='w')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
hdlr.setLevel(default_lvl)

AliceLog = {}
for p in phases:
    AliceLog[p] = logging.getLogger(p)
    AliceLog[p].addHandler(hdlr) 
    AliceLog[p].setLevel(default_lvl)


LocatorLog = AliceLog['locator']
ScoperLog = AliceLog['scoper']
RewriterLog = AliceLog['rewriter']
MainLog = AliceLog['main']

