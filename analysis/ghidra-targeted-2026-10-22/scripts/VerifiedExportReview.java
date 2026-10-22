// Applies only two previously proved fallthrough annotations in a fresh Ghidra project.
// Original PE bytes and Ghidra memory bytes are not patched.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.file.*;
import java.util.*;
public class VerifiedExportReview extends GhidraScript {
 public void run() throws Exception {
  String[] args=getScriptArgs();File out=new File(args[0]);out.mkdirs();Path scripts=Paths.get(args[1]);
  String expected="c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c";
  if(!expected.equals(currentProgram.getExecutableSHA256()))throw new Exception("Unexpected source hash");
  Address base=currentProgram.getImageBase(),start=base.add(0x22eff0L),end=base.add(0x22f625L);
  FunctionManager fm=currentProgram.getFunctionManager();Function old=fm.getFunctionAt(start);if(old!=null)fm.removeFunction(start);
  clearListing(start,end);AddressSet verifiedBody=new AddressSet();int verified=0;
  List<String> rows=Files.readAllLines(scripts.resolve("export-verified-instructions.tsv"));
  for(String row:rows) {
   String[] fields=row.split("\t");long rva=Long.decode(fields[0]);String hex=fields[1];int size=hex.length()/2;
   Address at=base.add(rva);byte[] bytes=new byte[size];currentProgram.getMemory().getBytes(at,bytes);
   for(int i=0;i<size;i++)if((bytes[i]&255)!=Integer.parseInt(hex.substring(2*i,2*i+2),16))throw new Exception("Byte mismatch at "+at);
   AddressSet restriction=new AddressSet(at,at.add(size-1));DisassembleCommand cmd=new DisassembleCommand(at,restriction,false);cmd.enableCodeAnalysis(false);cmd.applyTo(currentProgram,monitor);
   Instruction instruction=getInstructionAt(at);if(instruction==null||instruction.getLength()!=size)throw new Exception("Instruction boundary mismatch at "+at);
   verifiedBody.add(restriction);verified++;
  }
  PrintWriter annotations=new PrintWriter(new File(out,"export-fallthrough-annotations.tsv"));annotations.println("rva\tnew_fallthrough_rva\tjustification");
  for(String row:Files.readAllLines(scripts.resolve("export-proven-fallthroughs.tsv"))) {
   String[] fields=row.split("\t");Address from=base.add(Long.decode(fields[0])),to=base.add(Long.decode(fields[1]));
   Instruction instruction=getInstructionAt(from);instruction.setFallThrough(to);
   annotations.println(fields[0]+"\t"+fields[1]+"\tpreviously_proved_complementary_Jcc_pair");
  }
  annotations.close();Function f=fm.createFunction("review_export_with_proven_cfg",start,verifiedBody,SourceType.USER_DEFINED);
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);long t=System.currentTimeMillis();DecompileResults r=di.decompileFunction(f,45,monitor);
  boolean ok=r.decompileCompleted()&&r.getDecompiledFunction()!=null;
  try(PrintWriter code=new PrintWriter(new File(out,"wow_loader.dll.22eff0.verified-cfg.c"))) {
   code.println("/* Ghidra output with analyst-supplied CFG and two proved fallthrough annotations.");
   code.println("   Not raw decompilation, not independent verification of the supplied CFG, not original source. */");
   if(ok)code.println(r.getDecompiledFunction().getC());else code.println("/* FAILED: "+r.getErrorMessage()+" */");
  }
  try(PrintWriter meta=new PrintWriter(new File(out,"export-verified-cfg-summary.tsv"))) {
   meta.println("verified_instruction_count\tdecompile_api_completed\tms\terror");meta.println(verified+"\t"+ok+"\t"+(System.currentTimeMillis()-t)+"\t"+(r.getErrorMessage()==null?"":r.getErrorMessage().replace('\n',' ')));
  }
  // Recheck covered input bytes after annotations; no memory writes were used.
  for(String row:rows) {
   String[] fields=row.split("\t");Address at=base.add(Long.decode(fields[0]));String hex=fields[1];byte[] bytes=new byte[hex.length()/2];currentProgram.getMemory().getBytes(at,bytes);
   for(int i=0;i<bytes.length;i++)if((bytes[i]&255)!=Integer.parseInt(hex.substring(2*i,2*i+2),16))throw new Exception("Memory bytes changed");
  }
  di.dispose();println("VERIFIED_CFG_REVIEW completed="+ok+" byte_checks="+verified);
 }
}
