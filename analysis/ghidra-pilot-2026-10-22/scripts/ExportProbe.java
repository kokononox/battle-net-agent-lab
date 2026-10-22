import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
public class ExportProbe extends GhidraScript {
 public void run() throws Exception {
  PrintWriter p=new PrintWriter(new File(getScriptArgs()[0],currentProgram.getName()+".exports.c"));
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);
  AddressIterator it=currentProgram.getSymbolTable().getExternalEntryPointIterator();int n=0;
  while(it.hasNext() && n<10){Address a=it.next();Function f=currentProgram.getFunctionManager().getFunctionAt(a);if(f==null)continue;
   n++;p.println("/* Export "+f.getName()+" @ "+a+" */");DecompileResults d=di.decompileFunction(f,20,monitor);
   p.println(d.decompileCompleted()&&d.getDecompiledFunction()!=null?d.getDecompiledFunction().getC():d.getErrorMessage());
  }p.close();di.dispose();
 }
}
