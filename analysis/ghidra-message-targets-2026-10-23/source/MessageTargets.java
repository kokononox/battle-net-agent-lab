// Analysis only. No native PE execution, emulation, memory writes, patch, or CFG override.
// Four analyst-supplied extents: three pdata entries and one known entry-stub control.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
public class MessageTargets extends GhidraScript {
 String clean(String x) {return x==null?"":x.replace('\t',' ').replace('\r',' ').replace('\n',' ');}
 String hex(byte[] b) {StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
 String hash(byte[] b) throws Exception {return hex(MessageDigest.getInstance("SHA-256").digest(b));}
 public void run() throws Exception {
  String pin="1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a";
  if(!pin.equals(currentProgram.getExecutableSHA256()))throw new Exception("Unexpected input hash");
  if(currentProgram.getImageBase().getOffset()!=0x140000000L)throw new Exception("Unexpected image base");
  String[] args=getScriptArgs();File out=new File(args[0]);out.mkdirs();
  String[] lines=Files.readString(Path.of(args[1])).split("\\R");if(lines.length!=5)throw new Exception("Expected 4 requests");
  DecompInterface di=new DecompInterface();if(!di.openProgram(currentProgram))throw new Exception(di.getLastMessage());
  try(PrintWriter meta=new PrintWriter(new File(out,"results.tsv"));PrintWriter listing=new PrintWriter(new File(out,"listing.tsv"));PrintWriter env=new PrintWriter(new File(out,"program.txt"))) {
   env.println("language="+currentProgram.getLanguageID());env.println("compiler_spec="+currentProgram.getCompilerSpec().getCompilerSpecID());env.println("sha256="+currentProgram.getExecutableSHA256());env.println("image_base="+currentProgram.getImageBase());
   meta.println("role\trva\tend\tsha256_before\tsha256_after\tdisassembly_return\tentry_instruction_defined\tlisting_instructions\tdecompile_api_completed\tc_present\thalt_baddata_marker\tms\terror");
   listing.println("role\trva\tbytes\tassembly");
   for(int k=1;k<lines.length;k++) {
    String[] v=lines[k].split("\\t");String role=v[0];long rva=Long.parseUnsignedLong(v[1],16),endRva=Long.parseUnsignedLong(v[2],16);int len=(int)(endRva-rva);
    if(len<=0||len>4096)throw new Exception("Range bound");Address start=currentProgram.getImageBase().add(rva),end=currentProgram.getImageBase().add(endRva-1);byte[] before=new byte[len];currentProgram.getMemory().getBytes(start,before);String bh=hash(before);if(!bh.equals(v[3]))throw new Exception("Range bytes mismatch");
    boolean dis=false,entry=false,ok=false,hasC=false,hazard=false;long count=0,t=System.currentTimeMillis();String error="",c="";
    try {
     FunctionManager fm=currentProgram.getFunctionManager();if(fm.getFunctionAt(start)!=null)fm.removeFunction(start);clearListing(start,end);AddressSet body=new AddressSet(start,end);
     DisassembleCommand cmd=new DisassembleCommand(start,body,true);cmd.enableCodeAnalysis(false);dis=cmd.applyTo(currentProgram,monitor);entry=currentProgram.getListing().getInstructionAt(start)!=null;
     Function f=fm.createFunction("review_"+role,start,body,SourceType.USER_DEFINED);
     InstructionIterator it=currentProgram.getListing().getInstructions(body,true);while(it.hasNext()){Instruction i=it.next();count++;listing.println(role+"\t"+Long.toHexString(i.getAddress().subtract(currentProgram.getImageBase()))+"\t"+hex(i.getBytes())+"\t"+clean(i.toString()));}
     DecompileResults r=di.decompileFunction(f,30,monitor);ok=r.decompileCompleted();error=clean(r.getErrorMessage());hasC=r.getDecompiledFunction()!=null;if(hasC)c=r.getDecompiledFunction().getC();hazard=c.contains("halt_baddata");
    } catch(Exception e) {error=e.getClass().getSimpleName()+": "+clean(e.getMessage());}
    byte[] after=new byte[len];currentProgram.getMemory().getBytes(start,after);String ah=hash(after);if(!bh.equals(ah))throw new Exception("Analysis changed range bytes");
    try(PrintWriter code=new PrintWriter(new File(out,role+".raw.c"))){code.println("/* Raw Ghidra output, analyst-supplied extent; no semantic recovery claim. */");if(hasC)code.println(c);else code.println("/* No C output: "+error+" */");}
    meta.println(role+"\t"+v[1]+"\t"+v[2]+"\t"+bh+"\t"+ah+"\t"+dis+"\t"+entry+"\t"+count+"\t"+ok+"\t"+hasC+"\t"+hazard+"\t"+(System.currentTimeMillis()-t)+"\t"+error);meta.flush();listing.flush();println("MESSAGE_TARGET "+role+" API="+ok+" C="+hasC+" entry="+entry+" instructions="+count);
   }
  } finally {di.dispose();}
 }
}
