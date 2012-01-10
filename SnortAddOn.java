package snort.add.on;

import java.io.*;
import java.util.*;
/**
 *
 * @author Abdulellah Alsaheel
 */

class ip{
String Src;
String Dst;
public ip(String Src,String Dst){
this.Src = Src;
this.Dst = Dst;
}
}

class rule{
String sid,text,file;
boolean selected = true;
public rule(String sid, String text, String file){
this.sid = sid;
this.text = text;
this.file = file;
}
String getV(){
return sid;
}

}

class file{
String fileName;
ArrayList<rule> rules = new ArrayList<rule>();
boolean selected=true;
public file(String fileName){
this.fileName = fileName;
}
String getV(){
return fileName;
}
}

public class SnortAddOn {
static ArrayList<ip> ips = new ArrayList<ip>();
static ArrayList<file> files = new ArrayList<file>();

public static boolean notFound(String s , String d){
    for(int i=0;i<ips.size();i++)
    if(ips.get(i).Src.equals(s) && ips.get(i).Dst.equals(d))
    return false;
    return true;
}


public boolean isToday(String today,String day){
String[] date1;
String[] date2;
date1 = today.split("/");
date2 = day.split("/");
if(new Integer(date2[0]).intValue() > new Integer(date1[0]).intValue())
    return true;
else if(new Integer(date1[0]).intValue() == new Integer(date2[0]).intValue())
    if(new Integer(date2[1]).intValue() > new Integer(date1[1]).intValue())
        return true;
return false;
}

public boolean isTime(String time,String lastTime){
String[] time1;
String[] time2;
time1 = time.split(":");
time2 = lastTime.split(":");
if(new Integer(time2[0]).intValue() > new Integer(time1[0]).intValue())
    return true;
else if(new Integer(time1[0]).intValue() == new Integer(time2[0]).intValue())
    if(new Integer(time2[1]).intValue() > new Integer(time1[1]).intValue())
        return true;
    else if(new Integer(time1[1]).intValue() == new Integer(time2[1]).intValue())
    if(new  Double(time2[2]).doubleValue() > new  Double(time1[2]).doubleValue())
        return true;
return false;
}

public void loadRules(File file){
String line;
String[] forRegEx;
FileReader rulesreader;
BufferedReader rulesbReader;
int index = -1;
boolean isFound = false;

if(files.size()>0)
for(int i=0;i<files.size();i++)
if(file.getAbsolutePath().equals(files.get(i))){
index = i;
isFound = true;
}
if(!isFound){
    files.add(new file(file.getAbsolutePath()));
    index = files.size() - 1;
}
if(file.exists() && file.isFile()){
    try{
        rulesreader = new FileReader(file);
        rulesbReader = new BufferedReader(rulesreader);
        line = rulesbReader.readLine();
        while(line != null){
    line = rulesbReader.readLine();
    if(line != null)
    if(!line.isEmpty()){
    if(line.contains("alert") && !line.contains("#") && line.contains("sid:")){
    forRegEx = line.split("sid:");
    if(line.startsWith("sid:") && forRegEx[0].contains(";"))
    forRegEx = forRegEx[0].split(";");
    else if(line.contains("sid:") && forRegEx.length>1)
            forRegEx = forRegEx[1].split(";");

    files.get(index).rules.add(new rule(forRegEx[0],line,file.getAbsolutePath()));

    }
    }
        }
        
    }catch(NullPointerException e){
    System.out.print("NULL pointer Exception!");
    }catch(IOException e){
    System.out.print("I/O error!");
    }catch(Exception e){
    System.out.print("Exception");
    }

}
}

public void loadConf(File snort_conf){
String line;
String[] forRegEx;
String RULE_PATH = "";
String PREPROC_RULE_PATH = "";

if(snort_conf.exists()){
    try{
        FileReader rulesreader = new FileReader(snort_conf);
        BufferedReader rulesbReader = new BufferedReader(rulesreader);
        line = rulesbReader.readLine();
    while(line != null){
    line = rulesbReader.readLine();
    
    if(line != null)
    if(!line.isEmpty()){
    if(line.contains("var RULE_PATH ") && !line.contains("#")){
    forRegEx = line.split(" RULE_PATH ");
    RULE_PATH = forRegEx[1];
    }
    if(line.contains("var PREPROC_RULE_PATH ") && !line.contains("#")){
    forRegEx = line.split(" PREPROC_RULE_PATH ");
    PREPROC_RULE_PATH = forRegEx[1];
    }
    
    if(!RULE_PATH.equals("")){
    if(line.contains("include $RULE_PATH") && !line.contains("#")){
    forRegEx = line.split(" \\$RULE_PATH");
    loadRules(new File(RULE_PATH + forRegEx[1]));
    }
    }
    if(!PREPROC_RULE_PATH.equals(new String(""))){
    if(line.contains("include $PREPROC_RULE_PATH ") && !line.contains("#")){
    forRegEx = line.split(" \\$PREPROC_RULE_PATH");
    loadRules(new File(PREPROC_RULE_PATH + forRegEx[1]));
    }
    }
    }
        }
        
    }catch(NullPointerException e){
    System.out.print("NULL error!" + e.getMessage());
    }catch(IOException e){
    System.out.print("I/O error!");
    }catch(Exception e){
        System.out.print("Exception!");
    }

}
}
public void readAlert(File alertF,String honeypot,String conInf,String priority){
String line;
String lastID = "1";
String sid = "1";
String lastPriority= "4";
String lastSrc = "127.0.0.1";
String lastDst = "127.0.0.1";
String lastDay;
String today = "00/00";
String lastTime;
String time = "00:00:00.000000";
if(priority.isEmpty())
priority = "1";
String ID = "0";
String[] forRegEx;
boolean listed = false;
boolean changed = false;
boolean alertCompleted = false;
Runtime runtime = Runtime.getRuntime();
Process process;

try{
FileReader reader = new FileReader(alertF);
BufferedReader bReader = new BufferedReader(reader);
if(alertF.exists()){
    line = bReader.readLine();
    while(true){
    line = bReader.readLine();
    if(line == null){
    reader = new FileReader(alertF);
    bReader = new BufferedReader(reader);
    line = bReader.readLine();
    }
    line = new String(line + "\n");
    if(!line.isEmpty()){
    if(line.contains("[**] [")){
    forRegEx = line.split("[**] \\[");
    if(forRegEx[0].contains(" [**]")){
    forRegEx = forRegEx[0].split(":");
    sid = forRegEx[1];
    for(int i=0; i<files.size();i++){
    for(int j=0; j<files.get(i).rules.size();j++){
    if(sid.equals(files.get(i).rules.get(j).sid)){
    listed = true;
    break;
    }
    }
    }
    }
    }
    else if(listed){
    if(line.contains(" -> ")){
    forRegEx = line.split(" -> ");
    forRegEx = forRegEx[1].split(":");
    lastDst = forRegEx[0];
    forRegEx = line.split(" -> ");
    forRegEx = forRegEx[0].split(" ");
    forRegEx = forRegEx[1].split(":");
    lastSrc = forRegEx[0];
    forRegEx = line.split(" ");
    forRegEx = forRegEx[0].split("-");
    lastDay = forRegEx[0];
    lastTime = forRegEx[1];
    if(isToday(today,lastDay)){
    today = lastDay;
    time = forRegEx[1];
    changed = true;
    } else if(today.equals(lastDay))
    if(isTime(time,forRegEx[1])){
    time = lastTime;
    changed = true;
    }
        
    }
    if(line.contains("[Priority: ")){
    forRegEx = line.split("\\[Priority: ");
    if(forRegEx[1].contains("]")){
    forRegEx = forRegEx[1].split("]");
    lastPriority = forRegEx[0];
    }
    }

    if(line.contains("Len:"))
    alertCompleted = true;
    
    if(listed && changed && alertCompleted && new Integer(lastPriority).intValue() <= new Integer(priority).intValue()){
        if(lastSrc != honeypot && lastDst != honeypot)
        if(notFound(lastSrc,lastDst)){
        process = runtime.exec("iptables -t nat -A PREROUTING -p all -i " + conInf + " -s " + lastSrc + " -d " + lastDst + " -j DNAT --to-destination " + honeypot);
        process = runtime.exec("iptables -t nat -A POSTROUTING -p all -o " + conInf + " -s " + honeypot + " -d " + lastSrc + " -j SNAT --to-source " + lastDst);
        ips.add(new ip(lastSrc,lastDst));
        System.out.println("i did it!!");
    changed = false;
    listed = false;
    alertCompleted = false;
        }
    }
    }
    }
        }
    
}
}catch(NumberFormatException e){
System.out.println(e.getMessage());
}catch(FileNotFoundException e){
System.out.println("sorry the file is not available");
}catch(IOException e){
    System.out.print("I/O error!");
    }catch(Exception e){
    System.out.println(e.getMessage());
    }

}

    public void args(File config,File alert,String honeypot,String conInf,String priority){
    loadConf(config);
    readAlert(alert,honeypot,conInf,priority);
    }
    
    public static void main(String[] args) {
        File config,alert;
        String honeypot,priority,conInf;
        Scanner sc = new Scanner(System.in);
        System.out.println("please specify the snort configuration file location :");
        config = new File(sc.next());
        System.out.println("please specify the alert file location :");
        alert = new File(sc.next());
        System.out.println("please specify the honeypot ip :");
        honeypot = sc.next();
        System.out.println("please specify the configuered interface :");
        conInf = sc.next();
        System.out.println("please specify a priority which is triggering the redirecting :");
        priority = sc.next();
        SnortAddOn addOn = new SnortAddOn();
        addOn.args(config,alert,honeypot,conInf,priority);
    }
}

