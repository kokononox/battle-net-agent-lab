import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;
public class Probe extends GhidraScript {
 public void run() throws Exception {
  String[] a=getScriptArgs(); File dir=new File(a[0]);dir.mkdirs();
  PrintWriter meta=new PrintWriter(new File(dir,currentProgram.getName()+".summary.txt"));
  meta.println("Program: "+currentProgram.getName());meta.println("Language: "+currentProgram.getLanguageID());
  meta.println("Functions: "+currentProgram.getFunctionManager().getFunctionCount());
  meta.println("Instructions: "+currentProgram.getListing().getNumInstructions());
  meta.println("Memory blocks: "+currentProgram.getMemory().getBlocks().length);
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);
  FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);int tested=0,ok=0;
  PrintWriter code=new PrintWriter(new File(dir,currentProgram.getName()+".samples.c"));
  while(it.hasNext() && tested<12 && !monitor.isCancelled()){
   Function f=it.next();if(f.isThunk()||f.isExternal()||f.getBody().getNumAddresses()<40)continue;
   tested++;long t=System.currentTimeMillis();DecompileResults r=di.decompileFunction(f,20,monitor);
   meta.println("Sample "+f.getEntryPoint()+" "+f.getName()+" bytes="+f.getBody().getNumAddresses()+" success="+r.decompileCompleted()+" ms="+(System.currentTimeMillis()-t));
   if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){ok++;code.println("/* "+f.getEntryPoint()+" */\n"+r.getDecompiledFunction().getC());}else meta.println(r.getErrorMessage());
  }
  meta.println("Decompiled: "+ok+"/"+tested);code.close();meta.close();di.dispose();
 }
}
