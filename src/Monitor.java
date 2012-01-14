/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * monitor.java
 *
 * Created on Jan 8, 2012, 12:47:36 PM
 */


import java.io.*;
import java.util.*;
import javax.swing.*;
import java.awt.*;
/**
 *
 * @author a.alsaheel
 */

class dumper extends Thread{
Runtime runtime = Runtime.getRuntime();
Process process;
Monitor parent;

 public dumper(Monitor parent) {
this.parent =  parent;
 }
public void run(){
try{
       process = runtime.exec("tcpdump -nX -i " + parent.conInf);
       InputStream is = process.getInputStream();
       InputStreamReader isr = new InputStreamReader(is);
       BufferedReader in = new BufferedReader(isr,1024);
       String currentState;
       currentState = in.readLine();
       String[] forRegEx;
       String Src,Dst;

       while(true){
    if(currentState != null && parent.jComboBox1.getItemCount()!=0 && currentState.contains(" > ") && currentState.contains(parent.jComboBox1.getSelectedItem().toString())){
    for(int i=0;i<parent.ips.size();i++)
    if(currentState.contains(parent.ips.get(i).Src)){
if(parent.itemChanged){
    parent.itemChanged=false;
    parent.jTextArea1.setText("");
    break;
}
if(currentState != null && currentState.contains(" > "))
 parent.jTextArea1.append(currentState + "\n");
 currentState = in.readLine();

 while(currentState!=null && currentState.startsWith("\t")){
   if(parent.itemChanged){
       parent.itemChanged=false;
       parent.jTextArea1.setText("");
    break;
  }
  if(currentState!=null)
  parent.jTextArea1.append(currentState + "\n");
 currentState = in.readLine();
 }
break; 
}
                 }
    currentState = in.readLine();
                }
}catch(IOException e){
 System.out.print(e.getMessage());
 }catch(Exception e){
        System.out.print(e.getMessage());
    }
 
 
}
}

class ip{
String Src;
String Dst;
public ip(String Src,String Dst){
this.Src = Src;
this.Dst = Dst;
}
public String toString(){
return Src;
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

class readAlerts extends Thread{
Monitor parent;
File config,alert;
String honeypot,conInf,priority;

public readAlerts(Monitor parent,File config,File alert,String honeypot,String conInf,String priority){
this.parent = parent;
this.config = config;
this.alert = alert;
this.honeypot = honeypot;
this.conInf = conInf;
this.priority = priority;
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
    parent.loadRules(new File(RULE_PATH + forRegEx[1]));
    }
    }
    if(!PREPROC_RULE_PATH.equals(new String(""))){
    if(line.contains("include $PREPROC_RULE_PATH ") && !line.contains("#")){
    forRegEx = line.split(" \\$PREPROC_RULE_PATH");
    parent.loadRules(new File(PREPROC_RULE_PATH + forRegEx[1]));
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
    //System.out.print("alert file exist");

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
    for(int i=0; i<parent.files.size();i++){
    for(int j=0; j<parent.files.get(i).rules.size();j++){
    if(sid.equals(parent.files.get(i).rules.get(j).sid)){
    listed = true;
    break;
    }
    }
    }
    }
    }
    else if(listed){
    //if(true){
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
        if(parent.notFound(lastSrc,lastDst)){
        process = runtime.exec("iptables -t nat -A PREROUTING -p all -i " + conInf + " -s " + lastSrc + " -d " + lastDst + " -j DNAT --to-destination " + honeypot);
        process = runtime.exec("iptables -t nat -A POSTROUTING -p all -o " + conInf + " -s " + honeypot + " -d " + lastSrc + " -j SNAT --to-source " + lastDst);
        parent.ips.add(new ip(lastSrc,lastDst));
        parent.jComboBox1.addItem(new ip(lastSrc,lastDst));
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
public void run(){
loadConf(config);
readAlert(alert,honeypot,conInf,priority);
}
}
public class Monitor extends javax.swing.JFrame {
static ArrayList<file> files = new ArrayList<file>();
static ArrayList<String> rules = new ArrayList<String>();
static ArrayList<ip> ips = new ArrayList<ip>();
static ArrayList<ip> exIps = new ArrayList<ip>();

readAlerts reader;
dumper dump = new dumper(this);
String honeypot,conInf;
Runtime runtime = Runtime.getRuntime();
Process process;
boolean itemChanged = false;

public void args(File config,File alert,String honeypot,String conInf,String priority){
    this.honeypot = honeypot;
    this.conInf = conInf;
    this.reader = new readAlerts(this,config,alert,honeypot,conInf,priority);
    
    
    this.reader.start();
    this.dump.start();
    }

public static boolean notFound(String s , String d){
    for(int i=0;i<ips.size();i++)
    if(ips.get(i).Src.equals(s))
    return false;
    
    for(int i=0;i<exIps.size();i++)
    if(exIps.get(i).Src.equals(s))
    return false;
    
    return true;
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

    /** Creates new form monitor */
    public Monitor(){
        initComponents();
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
   
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel3 = new javax.swing.JPanel();
        jPanel2 = new javax.swing.JPanel();
        jComboBox2 = new javax.swing.JComboBox();
        jButton1 = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        jComboBox1 = new javax.swing.JComboBox();
        jButton2 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Excluded ip(s)"));

        jComboBox2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBox2ActionPerformed(evt);
            }
        });

        jButton1.setText("Redirect");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jComboBox2, 0, 143, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addComponent(jButton1)
                        .addGap(44, 44, 44))))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addComponent(jComboBox2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButton1))
        );

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Redirected ip(s)"));

        jComboBox1.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                jComboBox1ItemStateChanged(evt);
            }
        });
        jComboBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBox1ActionPerformed(evt);
            }
        });
        jComboBox1.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                jComboBox1KeyPressed(evt);
            }
        });

        jButton2.setText("Exclude");
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jComboBox1, 0, 143, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(47, 47, 47)
                        .addComponent(jButton2)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButton2))
        );

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 24));
        jLabel1.setText("SNORT REDIRECTOR");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 23, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addGap(28, 28, 28)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        jPanel3Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jPanel1, jPanel2});

        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addComponent(jLabel1))
                    .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(10, 10, 10)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 660, Short.MAX_VALUE))
                    .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 294, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
// TODO add your handling code here:
if(jComboBox2.getItemCount()!=0){
ip item = (ip) jComboBox2.getSelectedItem();
exIps.remove(item);
ips.add(item);
try{
process = runtime.exec("iptables -t nat -A PREROUTING -p all -i " + conInf + " -s " + item.Src + " -d " + item.Dst + " -j DNAT --to-destination " + honeypot);
process = runtime.exec("iptables -t nat -A POSTROUTING -p all -o " + conInf + " -s " + honeypot + " -d " + item.Src + " -j SNAT --to-source " + item.Dst);
}catch(Exception e){
    System.out.print(e.getMessage());
}
jComboBox2.removeItemAt(jComboBox2.getSelectedIndex());
jComboBox1.addItem(item);
}
}//GEN-LAST:event_jButton1ActionPerformed

private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
// TODO add your handling code here:
    itemChanged = true;
    this.jTextArea1.setText("");
}//GEN-LAST:event_jComboBox1ActionPerformed

private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
// TODO add your handling code here:
    jTextArea1.setText(""); 
    itemChanged = true;
}//GEN-LAST:event_jComboBox1ItemStateChanged

private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
// TODO add your handling code here:
itemChanged = true;
this.jTextArea1.setText("");
if(jComboBox1.getItemCount()!=0){
ip item = (ip) jComboBox1.getSelectedItem();
exIps.add(item);
ips.remove(item);
try{
process = runtime.exec("iptables -t nat -D PREROUTING -p all -i " + conInf + " -s " + item.Src + " -d " + item.Dst + " -j DNAT --to-destination " + honeypot);
process = runtime.exec("iptables -t nat -D POSTROUTING -p all -o " + conInf + " -s " + honeypot + " -d " + item.Src + " -j SNAT --to-source " + item.Dst);
}catch(Exception e){
    System.out.print(e.getMessage());
}
jComboBox1.removeItemAt(jComboBox1.getSelectedIndex());
jComboBox2.addItem(item);
}
}//GEN-LAST:event_jButton2ActionPerformed

private void jComboBox1KeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_jComboBox1KeyPressed
// TODO add your handling code here:
}//GEN-LAST:event_jComboBox1KeyPressed

private void jComboBox2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox2ActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_jComboBox2ActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Monitor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Monitor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Monitor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Monitor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                Monitor obj = new Monitor();
                Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
    
    // Determine the new location of the window
    int w = obj.getSize().width;
    int h = obj.getSize().height;
    int x = (dim.width-w)/2;
    int y = (dim.height-h)/2;
    
    // Move the window
    obj.setLocation(x, y);
                obj.setVisible(true);
                
                
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    public javax.swing.JButton jButton1;
    public javax.swing.JButton jButton2;
    public javax.swing.JComboBox jComboBox1;
    public javax.swing.JComboBox jComboBox2;
    public javax.swing.JLabel jLabel1;
    public javax.swing.JPanel jPanel1;
    public javax.swing.JPanel jPanel2;
    public javax.swing.JPanel jPanel3;
    public javax.swing.JScrollPane jScrollPane1;
    public javax.swing.JTextArea jTextArea1;
    // End of variables declaration//GEN-END:variables
}
