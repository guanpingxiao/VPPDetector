"""Original research-prototype scanner retained for reproducibility.

New integrations should import the :mod:`vppdetector` package instead.
"""

import os
import ast
import copy
import json
import time
import chardet
from Path.getPath import Path
from multiprocessing import Pool
from Tool.tool import cmp

#根据位置找定义, 并且不能含有*args或kwargs
class DefVisitor(ast.NodeVisitor):
    def __init__(self):
        self.target = False #假设不是满足条件的目标

    def setPos(self, position):
        self._position = position

    def setFlag(self, varargFlag, kwargFlag):
        self._varargFlag = varargFlag 
        self._kwargFlag = kwargFlag

    def visit_ClassDef(self, node):
        if node.lineno == self._position:
            flag1 = False
            flag2 = False
            for n in ast.iter_child_nodes(node):
                if isinstance(n, ast.FunctionDef):
                    if n.name == "__init__":
                        if self._varargFlag: #如果该函数在调用时被传递了*args，则定义中不能含有*args
                            try:
                                n.args.vararg.arg
                            except:
                                flag1 = True

                        if self._kwargFlag: #如果该函数在调用时被传递了**kwargs，则定义中不能含有**kwargs
                            try:
                                n.args.kwarg.arg
                            except:
                                flag2 = True


                        self.target = flag1 or flag2
                        return
        
        if not self.target: 
            self.generic_visit(node)


    def visit_FunctionDef(self, node):
        if node.lineno == self._position:
            flag1 = False
            flag2 = False
            if self._varargFlag: #如果该函数在调用时被传递了*args，则定义中不能含有*args
                try:
                    node.args.vararg.arg
                except:
                    flag1 = True

            if self._kwargFlag: #如果该函数在调用时被传递了**kwargs，则定义中不能含有**kwargs
                try:
                    node.args.kwarg.arg
                except:
                    flag2 = True
            
            self.target = flag1 or flag2
            return
        
        if not self.target: 
            self.generic_visit(node)


#寻找调用的API中含有*args或**kwargs的
class CallVisitor:
    def __init__(self):
        self.callDict = {}

    def clean(self):
        self.callDict.clear()
    
    def setName(self, varargName, kwargName):
        self._varargName = varargName
        self._kwargName = kwargName

    def dfsVisit(self, node):
        if isinstance(node, ast.Call):
            varargFlag = False #假设不存在*args
            kwargFlag = False #假设不存在**kwargs
            self.callName = ast.unparse(node.func)
            for arg in node.args:
                paraName = ast.unparse(arg)
                if paraName == f"*{self._varargName}": #传递的时候必须要带*号
                    varargFlag = True
                    break

            for keyword in node.keywords:
                paraName = ast.unparse(keyword)
                if paraName == f"**{self._kwargName}":
                    kwargFlag = True
                    break
            
            if varargFlag or kwargFlag:
                callName = ast.unparse(node.func)
                if callName not in self.callDict:
                    self.callDict[callName] = (node.lineno, varargFlag, kwargFlag)
                
                # print(callName, node.lineno)
                return
        
        for n in ast.iter_child_nodes(node):
            self.dfsVisit(n)



#根据函数名来找对应的位置，仅在当前文件中查找, API可能是类，也可能是函数
class ClassAndFunctionVisitor(ast.NodeVisitor):
    def __init__(self):
        self.positionLst = []
        self.noFindFlag = False #判断在当前文件中是否找到同名函数,假设找不到

    def clean(self):
        self.positionLst.clear()

    def setAPIName(self, name):
        self.APIName = name

    def visit_ClassDef(self, node):
        if node.name == self.APIName:
            self.positionLst.append(node.lineno)
        self.generic_visit(node)

    #从类中找定义的API
    def visitClasDef(self, root):
        for node in ast.iter_child_nodes(root):
            if isinstance(node, ast.ClassDef): #抽取类内API
                for n in ast.iter_child_nodes(node):
                    if isinstance(n, ast.FunctionDef):
                        if n.name == self.APIName:
                            flag = 1
                            for d in n.decorator_list:
                                if "overload" in ast.unparse(d): #含有overload装饰器的不算
                                    flag = 0
                                    break
                            if flag:
                                self.positionLst.append(n.lineno)

    #找普通的API 
    def visitFunctionDef(self, root):
        for node in ast.iter_child_nodes(root):
            if isinstance(node, ast.FunctionDef): #抽取类内API
                if node.name == self.APIName:
                    flag = 1
                    for d in node.decorator_list:
                        #若API定义中含有overload装饰器也排除
                        if "overload" in ast.unparse(d):
                            flag = 0
                            break
                    if flag:
                        self.positionLst.append(node.lineno)
    

    def visit_FunctionDef(self, node):
        if node.name == self.APIName:
            flag = 1
            for d in node.decorator_list:
                if "overload" in ast.unparse(d):
                    flag = 0
                    break
            if flag:
                self.positionLst.append(node.lineno)
        self.generic_visit(node)



class FunctionDefVisitor(ast.NodeVisitor):
    def __init__(self):
        self.lst = []
        self.defWithVariadicParaLst = [] #单独保存参数定义中含有可变参数的API
        self._callVisitor = CallVisitor() #
        self._findAPIPosition = ClassAndFunctionVisitor()
        self._callDefVisitor = DefVisitor()
        self.cnt1 = 0 #记录函数定义中含有*args或**kwargs的个数
        self.cnt2 = 0 #记录在内部将其传递给另一个函数的个数
        self.cnt3 = 0 #记录被传递的函数定义中不含有对应*arg或**kwargs的个数
        self._classStack = [] #保存类信息
        self._classNodeStack = [] #保存类节点
 
    
    def setRoot(self, root):
        self._root = root


    def setPrefix(self, prefix):
        self._prefix =  prefix #记录文件的路径
    

    def setEvolutionDict(self, evolutionDict): #设置变更字典
        self._evolutionDict = evolutionDict

    
    def clean(self):
        self._callVisitor.clean()
        self._findAPIPosition.clean()


    def cleanCnt(self):
        self.cnt1 = 0
        self.cnt2 = 0
        self.cnt3 = 0


    def findCallDef(self, callName, node, flag = 0):
        positionLst = []
        # 寻找callAPI定义的位置（可能会找到多个同名的API）
        self._findAPIPosition.setAPIName(callName)
        if flag == 0:
            self._findAPIPosition.visit(node)
        elif flag == 1:
            self._findAPIPosition.visitClasDef(node)
        else:
            self._findAPIPosition.visitFunctionDef(node)
        
        positionLst = copy.deepcopy(self._findAPIPosition.positionLst)
        self._findAPIPosition.positionLst.clear() #清空
        return positionLst 


    def findNoKwargCallDef(self, positionLst, varargFlag, kwargFlag):
        ansLst = []
        #根据位置查找callAPI的定义
        self._callDefVisitor.setFlag(varargFlag, kwargFlag)
        for pos in positionLst:
            self._callDefVisitor.setPos(pos) #设置位置信息
            self._callDefVisitor.visit(self._root) #根据位置在当前文件中查找
            if self._callDefVisitor.target:
                ansLst.append(pos)
                self._callDefVisitor.target = False
        
        return ansLst


    def visit_ClassDef(self, node):
        # 进入一个类定义时，当前类名进栈
        self._classStack.append(node.name)
        self._classNodeStack.append(node)
        self.generic_visit(node)
        # 离开类定义时，从栈中弹出类名和类节点
        self._classStack.pop()
        self._classNodeStack.pop()


    def visit_FunctionDef(self, node):
        #获取API定义中的参数
        paraLst = []
        for para in node.args.args + node.args.kwonlyargs:
            paraLst.append(ast.unparse(para))
       
        varargName = ""
        kwargName = ""
        varargFlag = True #假设有*args
        kwargFlag = True #假设有**kwargs
        try:
            varargName = node.args.vararg.arg
        except:
            varargFlag = False
        
        try:
            kwargName = node.args.kwarg.arg
        except:
            kwargFlag = False

        #step1: 找出参数定义中含有可变参数的API
        if varargFlag or kwargFlag: 
            currentClass = '.'.join(self._classStack) if self._classStack else ""
            if currentClass:
                fullPathName = self._prefix + '.' + currentClass + '.' + node.name
            else:
                fullPathName = self._prefix + '.' + node.name
            self.cnt1 += 1
            self.defWithVariadicParaLst.append({fullPathName: node.lineno}) 
            
            #step2: 再从函数体内找被传递*args或**kwargs的调用API
            self._callVisitor.setName(varargName, kwargName)
            self._callVisitor.dfsVisit(node)
            self.cnt2 += len(self._callVisitor.callDict)
            for callName, val in self._callVisitor.callDict.items():
                #如果调用API来自参数，则跳过
                if callName in paraLst:
                    continue
                
                callPos = val[0]
                varFlag = val[1]
                kwFlag = val[2]
                # 寻找callName定义的位置
                if 'self.' in callName:
                    callName = callName.replace("self.", "")
                
                if len(self._classNodeStack) > 0:
                    tempNode = self._classNodeStack[-1]
                    #若是通过self进行调用的，则优先在当前类中查找调用函数的定义
                    callDefPosLst = self.findCallDef(callName, tempNode)
                    
                    #若当前类找不到，则再从当前文件进行查找，但也只从类中查找
                    if len(callDefPosLst) == 0:
                        callDefPosLst = self.findCallDef(callName, self._root, 1)
                else:
                    #只查找普通函数
                    callDefPosLst = self.findCallDef(callName, self._root, 2)
                
                if len(callDefPosLst) > 0:
                    #再从这些API里筛选出参数定义中不含可变参数的API
                    callDefNoKwargPosLst = self.findNoKwargCallDef(callDefPosLst, varFlag, kwFlag)
                    if len(callDefNoKwargPosLst):
                        tempDict = {fullPathName: node.lineno, callName: (callPos, str(callDefNoKwargPosLst))}
                        if len(callDefNoKwargPosLst) == 1:
                            self.cnt3 += 1 
                            self.lst.append(tempDict)
                
            self.clean()  # 清理
        
        self.generic_visit(node)


# 获取文件的编码方式
def getEncoding(filePath):
    # 读取二进制文件内容
    with open(filePath, "rb") as f:
        raw_data = f.read()
    # 自动检测文件编码
    result = chardet.detect(raw_data)
    encoding = result['encoding']
    return encoding


#libName = torch1.5.1
#/home/zhang/Packages/Matplotlib/matplotlibxx.xx
def getPrefix(filePath, libName):
    index=-1
    for i in range(len(libName)):
        if libName[i].isdigit():
            index=i
            break
    #rstrip在去除的时候是不考虑字符的顺序的，比如"xxxxapi.py".rstrip(',pyi')就会出错
    #s=filePath.split(f"{projName}")[-1].replace('/','.').rstrip('.pyi').rstrip('.py')
    s=filePath.split(f"{libName}")[-1].replace('/','.')
    pos=s.rfind('.') #bug修复2023.9.8
    s=s[0:pos]
    prefix=libName[0:index] + s
    return prefix


def getVersion(s):
    index = 0
    for i, ch in enumerate(s):
        if ch.isdigit():
            index = i
            break
    return  s[index:]



def getKwargAPI(libName):
    pathObj1 = Path("D")
    pathObj1.getPath(f"/home/zhang/Packages/{libName}") #库源码路径
    libPath = pathObj1.path
    visitor = FunctionDefVisitor()
    
    os.makedirs(f"KWARGS/APIDefWithVariadicPara/{libName}", exist_ok=True)
    os.makedirs(f"KWARGS/VariadicParaPitfalls/{libName}", exist_ok=True)
    
    cntDict = {} #计数字典，保存所有版本的数据
    for lib in libPath: #版本库路径
        libNameAndVersion = lib.split('/')[-1]
        dic = {}
        defDict = {}
        pathObj2 = Path("DF")
        pathObj2.getPath(lib) #获取当前库版本下的所有文件
        codeFilePath = pathObj2.path
        for codeFile in codeFilePath:
            prefix = getPrefix(codeFile, libNameAndVersion)
            visitor.setPrefix(prefix)
            try:
                encdoing = getEncoding(codeFile)  # 获取文件编码方式
                with open(codeFile, 'r', encoding = encdoing) as fr:
                    codeText = fr.read()
                root = ast.parse(codeText, filename='<unknown>', mode='exec')
            except:
                continue

            visitor.setRoot(root)
            try:
                visitor.visit(root)
            except:
                print(codeFile)

            if len(visitor.defWithVariadicParaLst) > 0:
                lst = copy.deepcopy(visitor.defWithVariadicParaLst)
                defDict[codeFile] = lst
                visitor.defWithVariadicParaLst.clear()

            if len(visitor.lst) > 0:
                lst = copy.deepcopy(visitor.lst)
                dic[codeFile] = lst
                visitor.lst.clear()

        #保存当前版本的情况
        fileName = lib.split("/")[-1]
        if len(defDict) > 0:
            with open(f"KWARGS/APIDefWithVariadicPara/{libName}/{fileName}.txt", 'w') as fw:
                json.dump(defDict, fw, indent=4, ensure_ascii=False)
        
        if len(dic) > 0:
            with open(f"KWARGS/VariadicParaPitfalls/{libName}/{fileName}.txt", 'w') as fw:
                json.dump(dic, fw, indent=4, ensure_ascii=False)
        


        #保存当前版本库的计数
        cntDict[fileName] = (visitor.cnt1, visitor.cnt2, visitor.cnt3)
        visitor.cleanCnt()

    sortedDict=dict(sorted(cntDict.items(), key=lambda it: cmp(getVersion(it[0]))))
    sortedDict = cntDict
    with open(f"KWARGS/VariadicParaPitfalls/{libName}/count", 'w') as fw:
        json.dump(sortedDict, fw, indent=4, ensure_ascii=False)

    print(libName)


libLst = [
"aiohttp", "click", "dask", "django", "faker", "fastapi", "flask", "gensim", "httpx", "jax", "keras",
"lightgbm", "loguru", "matplotlib", "networkx", "numpy", "pandas", "PIL", "plotly", "polars", "pydantic", "redis",
"requests", "rich", "scipy", "sklearn", "spacy", "sympy", "tensorflow", "torch", "tornado", "transformers", "xgboost"
]


if __name__ == '__main__':
    start = time.time()
    pool=Pool(20)
    pool.map(getKwargAPI, libLst)
    pool.close()
    pool.join()
    end = time.time()
    print(f"Total run time={(end-start)/3600:.2f} hour")
