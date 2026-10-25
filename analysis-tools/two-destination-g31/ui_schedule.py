"""Pure timing policy, never an authority to invoke a UI action."""
def install_due(elapsed,last,count):
 return 0<=elapsed<165 and 0<=count<12 and elapsed-last>=14
