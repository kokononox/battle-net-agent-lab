"""Bounded read-only retries ONLY before an action helper ever started."""
class Poll:
    def __init__(self): self.checks=0; self.last=None
    def due(self,elapsed,result):
        if self.checks>=12 or elapsed<5 or (self.last is not None and elapsed-self.last<10):return False
        if self.checks and not (result.get('status')=='no_targets' and result.get('helper_started') is False and result.get('outcome_uncertain') is False and all(result.get(k) is False for k in ('selection_attempted','selection_confirmed','continue_attempted','continue_returned'))):return False
        self.checks+=1;self.last=elapsed;return True

def keep(report,gui):
    """Keep first and latest pre-final snapshot; final existing snapshot makes <=3."""
    rows=report['gui_observations']
    if len(rows)<2:rows.append(gui)
    else:rows[1]=gui
