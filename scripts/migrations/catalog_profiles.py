"""Closed legacy catalogue profiles. Never derive permissions from observed drift."""
import copy


def private_policy_trigger(catalog):
    """An owner-created predecessor trigger retains its private default ACL.

    The ordinary immutable legacy runner can instead retain PUBLIC EXECUTE on
    this one trigger function. Preserve both authenticated installation paths;
    all other catalogue fields and all other privilege bits stay exact.
    """
    result=copy.deepcopy(catalog)
    rows=[row for row in result['functions'] if row[:3]==['openpc','reject_policy_immutable_mutation','']]
    if len(rows)!=1:raise ValueError('Missing qualified policy trigger identity')
    row=rows[0]
    public=['PUBLIC','EXECUTE',False,'openpc_control_owner']
    owner=['openpc_control_owner','EXECUTE',False,'openpc_control_owner']
    if row[3]!='openpc_control_owner' or row[4]!=[public,owner] or 'RETURNS trigger' not in row[5]:
        raise ValueError('Unrecognized policy trigger owner, permissions or function kind')
    row[4]=[owner]
    return result
