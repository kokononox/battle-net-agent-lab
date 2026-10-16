"""Bounded, in-memory Agent-9824 allocation/rollback model, NOT a file writer.
Observed first-fit and 480-byte archive-prefix reservation paths only. Extra
input checks are our fixture policy, not demonstrated Agent rejection rules.
"""
import struct
import patch_audit as a
import shmem_primary_readonly as p
SEGMENT=1<<30
PREFIX=0x1e0

def records(raw):
    p.inspect(raw)
    count=struct.unpack_from('<I',raw,4)[0]
    rows=[(int.from_bytes(raw[p.ARRAY_A+i*5:p.ARRAY_A+(i+1)*5],'big'),int.from_bytes(raw[p.ARRAY_B+i*5:p.ARRAY_B+(i+1)*5],'big')) for i in range(count)]
    a.require(all(0<=start<p.LIMIT and start+length<=p.LIMIT and length<=SEGMENT and start%SEGMENT+length<=SEGMENT for length,start in rows),'allocator_fixture_range_policy')
    intervals=sorted((start,start+length) for length,start in rows if length)
    a.require(all(left[1]<=right[0] for left,right in zip(intervals,intervals[1:])),'allocator_fixture_overlap_policy')
    return rows

def make(rows):
    a.require(isinstance(rows,list) and len(rows)<=p.CAPACITY,'allocator_fixture_count')
    raw=bytearray(p.SIZE);struct.pack_into('<II',raw,0,1,len(rows))
    for i,row in enumerate(rows):
        a.require(isinstance(row,tuple) and len(row)==2 and all(type(v)is int and 0<=v<p.LIMIT for v in row),'allocator_fixture_row')
        length,start=row;a.require(start+length<=p.LIMIT,'allocator_fixture_range_policy')
        raw[p.ARRAY_A+i*5:p.ARRAY_A+(i+1)*5]=length.to_bytes(5,'big')
        raw[p.ARRAY_B+i*5:p.ARRAY_B+(i+1)*5]=start.to_bytes(5,'big')
    records(bytes(raw));return bytes(raw)

def recover(raw):
    rows=records(raw);state=struct.unpack_from('<I',raw)[0]
    if state!=2:return raw
    index=struct.unpack_from('<I',raw,8)[0];saved_b,saved_a=struct.unpack_from('<QQ',raw,0x10)
    out=bytearray(raw);out[p.ARRAY_B+5*index:p.ARRAY_B+5*(index+1)]=saved_b.to_bytes(5,'big');out[p.ARRAY_A+5*index:p.ARRAY_A+5*(index+1)]=saved_a.to_bytes(5,'big');struct.pack_into('<I',out,0,1)
    records(bytes(out));return bytes(out)

def update_frames(raw,index,new_a,new_b):
    rows=records(raw);a.require(struct.unpack_from('<I',raw)[0]==1,'allocator_state_one_required')
    a.require(type(index)is int and 0<=index<len(rows),'allocator_update_index')
    a.require(all(type(v)is int and 0<=v<p.LIMIT for v in (new_a,new_b)) and new_a+new_b<=p.LIMIT,'allocator_update_range')
    candidate=list(rows);candidate[index]=(new_a,new_b);make(candidate)  # validate final fixture policy before emitting frames
    old_a,old_b=rows[index];out=bytearray(raw)
    frames=[('old',bytes(out))]
    struct.pack_into('<I',out,8,index);struct.pack_into('<QQ',out,0x10,old_b,old_a);frames.append(('saved',bytes(out)))
    struct.pack_into('<I',out,0,2);frames.append(('marked_two',bytes(out)))
    out[p.ARRAY_A+5*index:p.ARRAY_A+5*(index+1)]=new_a.to_bytes(5,'big');frames.append(('array_a_written',bytes(out)))
    out[p.ARRAY_B+5*index:p.ARRAY_B+5*(index+1)]=new_b.to_bytes(5,'big');frames.append(('array_b_written',bytes(out)))
    struct.pack_into('<I',out,0,1);frames.append(('committed_one',bytes(out)))
    return frames

def allocate(raw,size):
    a.require(type(size)is int and 0<=size<1<<32,'allocator_request_policy')
    raw=recover(raw);rows=records(raw)
    if struct.unpack_from('<I',raw)[0]!=1:return {'code':14,'payload':raw}
    if size==0:return {'code':0,'address':0,'size':0,'payload':raw,'index':None}
    for i,(length,start) in enumerate(rows):
        if length<size:continue
        if start%SEGMENT==0 and length>=PREFIX:
            return {'code':16,'address':start,'size':length,'payload':raw,'index':i}
        frames=update_frames(raw,i,length-size,start+size)
        return {'code':0,'address':start,'size':size,'payload':frames[-1][1],'index':i}
    return {'code':14,'payload':raw}

def reserve_prefix(raw,archive):
    a.require(type(archive)is int and 0<=archive<1024,'allocator_archive_policy')
    raw=recover(raw);rows=records(raw);low=archive*SEGMENT;high=low+PREFIX
    if struct.unpack_from('<I',raw)[0]!=1:return {'code':14,'payload':raw}
    for i,(length,start) in enumerate(rows):
        if start<=low and start+length>=high:
            out=update_frames(raw,i,start+length-high,high)[-1][1]
            return {'code':0,'payload':out,'index':i}
    return {'code':14,'payload':raw}
