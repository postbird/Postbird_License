using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.IO;
using System.Net;

namespace SXWTaxCalculation
{
    class License
    {
        //key
        private string key = "license(postbird_license^postbird$www.ptbird.cn@2016#)";
        //checkstatus
        private string checkStatus = "yes+post^bird";
        //file
        private string file = "License.postbird_license";
        //cpu 
        private string cpuId = "";
        //硬盘id
        private string diskId = "";
        //mac地址
        private string macAddress = "";
        //计算机名
        private string computerName = "";
        //机器码
        private string guid = "";
        //请求验证的url
       
        private string url = "http://127.0.0.1/regist.php/";

       //初始化的构造函数里面进行了很多加密
       //但是我也忘记了都加密了什么....真的忘记了 很蛋疼
       //或许这才是加密比较高的境界吧哈哈哈哈
       //这个里面主要用了des和MD5其实可以自己在使用别的加密方式的
        public License()
        {
            this.getCpuId();
            this.getDiskId();
            this.getMacAddress();
            this.getComputerName();
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] output = md5.ComputeHash(Encoding.Default.GetBytes(key));
            this.key = BitConverter.ToString(output);
            this.guid = BitConverter.ToString(md5.ComputeHash(Encoding.Default.GetBytes(this.cpuId + this.diskId + this.macAddress)));
            this.checkStatus= BitConverter.ToString(md5.ComputeHash(Encoding.Default.GetBytes(this.checkStatus)));
            this.checkStatus = this.checkStatus + this.guid;
            this.checkStatus = BitConverter.ToString(md5.ComputeHash(Encoding.Default.GetBytes(this.checkStatus)));
        }
        public string getMac ()
        {
            return this.macAddress;
        }
            //验证license中机器码是否与本机的机器码一致，如果不一致要求注册
            //如果文件不存在也要求注册
            public bool checkCode()
            {
            //验证guid和文件是否存在
            try
            {
            if (File.Exists(@""+""+this.file))
            {
                StreamReader sr = new StreamReader(this.file, Encoding.Default);
                string line;
                if ((line = sr.ReadLine()) != null)
                {
                    string tmpGuid=this.Decrypt(line); //需要解密
                    //验证记录的id与当前机器是否一样
                    //不一样则需要进行注册 如果一样则验证状态吗是否是开启的
                    if (tmpGuid.Equals(this.guid))
                    {
                        //读取第二行
                        if ((line = sr.ReadLine()) != null)
                        {
                            tmpGuid = this.Decrypt(line);//需要解密
                            if (tmpGuid.Equals(this.checkStatus))
                            {
                                sr.Close();
                                return true;
                            }
                        }
                    }
                }
                sr.Close();
            }
            return false;
            }catch(Exception ex){
            return false;
            }
        }
        //1 ok
        //2 上限
        //0 no
        public int registSoftware(string name,string code,string check)
        {
            //首先将机器码写入本地计算机 覆盖写入
            StreamWriter sw = new StreamWriter(this.file);
            string line = this.Encrypt(this.guid);//需要加密
            sw.WriteLine(line);
            sw.Flush();
            sw.Close();
            //机器码需要上传到服务器
            //服务器有名字/注册码/验证码/机器码四个选项,机器码是控制计算机的使用 比如最多3台计算机
            if (name.Trim().Length==0 || code.Trim().Length == 0 || check.Trim().Length == 0)
            {
                return 0;
            }else
            {
                try
                {
                    //发送请求
                    //构造参数
                    string param = "ie=utf-8&source=txt&query=hello&name=" + name + "&code=" + code + "&check=" + check + "&mac=" + this.macAddress + "&t=8a7dcbacb3ed72cad9f3fb079809a127&token=cad9f3fb079809a1278a7dcbacb3ed72";
                    //设置编码
                    Encoding encode = Encoding.GetEncoding("utf-8");
                    //解析参数字符串
                    byte[] arrB = encode.GetBytes(param);
                    //创建请求
                    HttpWebRequest myReq = (HttpWebRequest)WebRequest.Create(this.url);
                    myReq.Method = "POST";
                    myReq.ContentType = "application/x-www-form-urlencoded";
                    myReq.ContentLength = arrB.Length;
                    Stream outStream = myReq.GetRequestStream();
                    outStream.Write(arrB, 0, arrB.Length);
                    outStream.Close();
                    //接收HTTP做出的响应
                    WebResponse myResp = myReq.GetResponse();
                    Stream ReceiveStream = myResp.GetResponseStream();
                    StreamReader readStream = new StreamReader(ReceiveStream, encode);
                    Char[] read = new Char[256];
                    int count = readStream.Read(read, 0, 256);
                    string strRes = null;//结果
                    while (count > 0)
                    {
                        strRes += new String(read, 0, count);
                        count = readStream.Read(read, 0, 256);
                    }
                    readStream.Close();
                    myResp.Close();
                    //验证成功将状态码写入 追加写入
                    // strRes ok-success no-max no-failed
                    if (strRes.Contains("ok")){
                        sw = new StreamWriter(this.file, true);
                        line = this.Encrypt(this.checkStatus);//需要加密
                        sw.WriteLine(line);
                        sw.Flush();
                        sw.Close();
                        return 1;
                    }else if(strRes.Contains("max"))
                    {
                        return 2;
                    }else
                    {
                        return 0;
                    }
                }
                catch
                {
                    return 0;
                }
            }
        }
       // DES加密和解密
       private string  Encrypt(string str)
        {
            try
            {
                DESCryptoServiceProvider descsp = new DESCryptoServiceProvider();   //实例化加/解密类对象   

                byte[] tmpKey = Encoding.Unicode.GetBytes(this.key.Substring(0,4)); //定义字节数组，用来存储密钥   key必须是八位的  

                byte[] data = Encoding.Unicode.GetBytes(str);//定义字节数组，用来存储要加密的字符串  

                MemoryStream MStream = new MemoryStream(); //实例化内存流对象      

                //使用内存流实例化加密流对象   
                CryptoStream CStream = new CryptoStream(MStream, descsp.CreateEncryptor(tmpKey, tmpKey), CryptoStreamMode.Write);

                CStream.Write(data, 0, data.Length);  //向加密流中写入数据      

                CStream.FlushFinalBlock();              //释放加密流      

                return Convert.ToBase64String(MStream.ToArray());//返回加密后的字符串  
            }catch
            {
              return str;
            }
            
        }

private string Decrypt(string str)
{
try
{
    DESCryptoServiceProvider descsp = new DESCryptoServiceProvider();   //实例化加/解密类对象    

    byte[] tmpKey = Encoding.Unicode.GetBytes(this.key.Substring(0,4)); //定义字节数组，用来存储密钥       key必须是八位的  

    byte[] data = Convert.FromBase64String(str);//定义字节数组，用来存储要解密的字符串  

    MemoryStream MStream = new MemoryStream(); //实例化内存流对象      

    //使用内存流实例化解密流对象       
    CryptoStream CStream = new CryptoStream(MStream, descsp.CreateDecryptor(tmpKey, tmpKey), CryptoStreamMode.Write);

    CStream.Write(data, 0, data.Length);      //向解密流中写入数据     

    CStream.FlushFinalBlock();               //释放解密流      

    return Encoding.Unicode.GetString(MStream.ToArray());       //返回解密后的字符串  
}
catch
{
    return str;
}
}

        //1.获取CPU序列号代码 
        private void  getCpuId()
        {
            try
            {
                ManagementClass mc = new ManagementClass("Win32_Processor");
                ManagementObjectCollection moc = mc.GetInstances();
                foreach (ManagementObject mo in moc)
                {
                    this.cpuId = mo.Properties["ProcessorId"].Value.ToString();
                }
                moc = null;
                mc = null;
            }
            catch
            {
                this.cpuId = "postbird-cpuid-unknown";
            }
            finally
            {

            }
        }
        //3.获取硬盘ID 
        private void getDiskId()
        {
            try
            {
                ManagementClass mc = new ManagementClass("Win32_DiskDrive");
                ManagementObjectCollection moc = mc.GetInstances();
                foreach (ManagementObject mo in moc)
                {
                    this.diskId = (string)mo.Properties["Model"].Value;
                }
                moc = null;
                mc = null;
            }
            catch
            {
                this.diskId= "postbird-diskid-unknown";
            }
            finally
            {
            }

        }
        //2.获取网卡硬件地址 
        private void getMacAddress()
        {
            try
            {
                ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
                ManagementObjectCollection moc = mc.GetInstances();
                foreach (ManagementObject mo in moc)
                {
                    if ((bool)mo["IPEnabled"] == true)
                    {
                        this.macAddress = mo["MacAddress"].ToString();
                        break;
                    }
                }
                moc = null;
                mc = null;
            }
            catch
            {
                this.macAddress= "postbird-maxaddress-unknown";
            }
            finally
            {
            }

        }
        //6.获取计算机名
        private void getComputerName()
        {
            try
            {
                this.computerName= System.Environment.MachineName;

            }
            catch
            {
                this.computerName = "postbird-computername-unknown";
            }
            finally
            {
            }
        }
    }
}
