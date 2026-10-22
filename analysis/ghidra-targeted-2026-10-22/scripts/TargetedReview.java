// Targeted, analysis-only decompilation. No execution/emulation or byte patches.
// Function extents are analyst-supplied from PE unwind metadata / tiny validated stubs.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
public class TargetedReview extends GhidraScript {
 public void run() throws Exception {
  File out=new File(getScriptArgs()[0]);out.mkdirs();
  boolean loader=currentProgram.getName().equalsIgnoreCase("wow_loader.dll");
  String expectedHash=loader?"c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c":"1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a";
  if(!expectedHash.equals(currentProgram.getExecutableSHA256()))throw new Exception("Unexpected input file hash");
  long[][] ranges=loader?new long[][]{{0x2006630L,0x200666dL},{0x2006670L,0x200671cL},{0x2006508L,0x2006630L},{0x1beb830L,0x1beba45L},{0x22eff0L,0x22f626L}}:new long[][]{{0x1da9b0L,0x1da9c9L},{0x1da9e0L,0x1da9e3L}};
  String[] names=loader?new String[]{"review_dll_entry","review_cookie_initializer_candidate","review_startup_dispatch","review_application_body_unresolved","review_export_ordinal_1"}:new String[]{"review_exe_entry_stub","review_tls_callback_stub"};
  PrintWriter meta=new PrintWriter(new File(out,currentProgram.getName()+".targeted.tsv"));
  meta.println("name\trva\tend_rva\tbody_source\tlisting_instructions\tdisassembly_ok\tdecompile_api_completed\tms\terror");
  Function[] fs=new Function[ranges.length];boolean[] disOk=new boolean[ranges.length];
  FunctionManager fm=currentProgram.getFunctionManager();Address base=currentProgram.getImageBase();
  for(int k=0;k<ranges.length;k++) {
   Address start=base.add(ranges[k][0]),end=base.add(ranges[k][1]-1);AddressSet body=new AddressSet(start,end);
   Function old=fm.getFunctionAt(start);if(old!=null)fm.removeFunction(start);
   clearListing(start,end);
   DisassembleCommand cmd=new DisassembleCommand(start,body,true);cmd.enableCodeAnalysis(false);
   disOk[k]=cmd.applyTo(currentProgram,monitor);
   fs[k]=fm.createFunction(names[k],start,body,SourceType.USER_DEFINED);
  }
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);
  for(int k=0;k<fs.length;k++) {
   Function f=fs[k];long count=0;InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);while(ii.hasNext()){ii.next();count++;}
   long t=System.currentTimeMillis();DecompileResults r=di.decompileFunction(f,30,monitor);String err=r.getErrorMessage();
   boolean ok=r.decompileCompleted()&&r.getDecompiledFunction()!=null;
   String filename=currentProgram.getName()+"."+Long.toHexString(ranges[k][0])+".raw.c";
   try(PrintWriter code=new PrintWriter(new File(out,filename))) {
    code.println("/* Raw Ghidra 12.2 output; analyst-supplied function extent; no type/signature corrections.");
    code.println("   API completion is not proof of semantic correctness. Original PE bytes unchanged. */");
    code.println("/* RVA "+Long.toHexString(ranges[k][0])+".."+Long.toHexString(ranges[k][1])+" */");
    if(ok)code.println(r.getDecompiledFunction().getC());else code.println("/* Decompilation failed: "+err+" */");
   }
   meta.println(names[k]+"\t0x"+Long.toHexString(ranges[k][0])+"\t0x"+Long.toHexString(ranges[k][1])+"\tanalyst_supplied\t"+count+"\t"+disOk[k]+"\t"+ok+"\t"+(System.currentTimeMillis()-t)+"\t"+(err==null?"":err.replace('\n',' ').replace('\t',' ')));
   meta.flush();println("TARGET_REVIEW "+filename+" completed="+ok+" instructions="+count);
  }
  di.dispose();meta.close();
 }
}
