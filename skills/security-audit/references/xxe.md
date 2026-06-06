# XXE 漏洞审计指南

## 漏洞定义

XML 外部实体注入（XXE）攻击是指攻击者通过在 XML 文档中注入外部实体，来读取服务器上的文件或执行其他恶意操作。

## CWE 分类

- **CWE-611**: XXE

## 严重性评估

- **Critical**: 可读取任意文件、执行系统命令
- **High**: 可读取内部文件、探测内网
- **Medium**: 需要特定条件才能利用

## 检测方法

### 1. 搜索危险函数

```python
# Python
"xml.etree.ElementTree", "ET.parse"
"xml.dom.minidom", "xml.dom.pulldom"
"lxml.etree", "etree.parse"
"defusedxml", "ElementTree"
"yaml.load"  # YAML 也可能支持 XXE

# Java
"DocumentBuilder", "SAXParser", "XMLStreamReader"
"TransformerFactory", "Unmarshaller"
"@XmlElement", "@XmlRootElement"  # JAXB

# PHP
"simplexml_load_string", "simplexml_load_file"
"DOMDocument", "loadXML", "loadHTML"
```

### 2. 识别用户输入来源

```python
"request.args", "request.form", "request.body"
"$_GET", "$_POST", "$_REQUEST"
"req.body", "@RequestBody"
```

## 验证步骤

### 1. 确认 XML 解析方式

```python
# 危险示例
import xml.etree.ElementTree as ET

xml_data = request.body
tree = ET.parse(xml_data)  # 默认启用 XXE

# 安全示例
from defusedxml import ElementTree

xml_data = request.body
tree = ElementTree.parse(xml_data)  # 安全解析器
```

### 2. 检查防护措施

- **禁用外部实体**: `resolve_entities=False`
- **使用安全解析器**: defusedxml
- **禁止 DTD**: `dtd_validation=False`

## 修复建议

### Python

```python
# 使用 defusedxml（推荐）
from defusedxml import ElementTree

xml_data = request.body
tree = ElementTree.parse(xml_data)

# 或者禁用外部实体
import xml.etree.ElementTree as ET

xml_data = request.body
# Python 3.8+ 默认禁用 XXE
tree = ET.parse(xml_data)
```

### Java

```java
// 不安全的配置
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// 安全配置
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

### PHP

```php
// 不安全
$xml = simplexml_load_string($userInput);

// 安全
libxml_use_internal_errors(true);
$xml = simplexml_load_string($userInput, 'SimpleXMLElement', LIBXML_NONET);
libxml_disable_entity_loader(true);
```

## 报告模板

```
#### [严重性] XXE 漏洞

- **位置**: `file.py:123`
- **漏洞类型**: XML External Entity
- **CWE**: CWE-611
- **描述**: XML 解析器未禁用外部实体
- **代码片段**: ...
- **修复建议**: 使用安全的 XML 解析配置或 defusedxml 库
```