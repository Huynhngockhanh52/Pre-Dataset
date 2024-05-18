# =========================================================================
# Copyright (C) 2016-2023 LOGPAI (https://github.com/logpai).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =========================================================================

import regex as re
import os
import pandas as pd
import hashlib
from datetime import datetime

class Logcluster:
    """
    Class Logcluster (là một đối tượng LOG GROUP), được sử dụng để thực hiện quá trình lưu trữ thông tin của một nhóm log, bao gồm: 
    
    Thuộc tính:
    -----------
        - `logTemplate`: Template đặc trưng của nhóm log đó
        - `logIDL`: Danh sách các ID message log thuộc nhóm log trên
    """
    def __init__(self, logTemplate="", logIDL=None):
        self.logTemplate = logTemplate
        if logIDL is None:
            logIDL = []
        self.logIDL = logIDL

class Node:
    """
    Class Node là các node có trong cây phân tách - parser tree. Parser Tree có 01 Root node, internal node: lớp 1 là các node chứa chiều dài của chuỗi, tiếp theo là các internal node token, cuối cùng là leaf node.
    
    Thuộc tính:
    ----------
    - `childD`: Các Node của Node hiện tại - là một dictionary đối với internal node và list với leaf node: Nhiệm vụ chứa địa chỉ các Node con.
    - `depth`: Độ sâu của node hiện tại
    - `digitOrtoken`: Token mà node hiện tại đang chứa
    """
    def __init__(self, childD=None, depth=0, digitOrtoken=None):
        if childD is None:
            childD = dict()
        self.childD = childD
        self.depth = depth
        self.digitOrtoken = digitOrtoken

class LogParser:
    """
        Class `LogParser` bao gồm các phương thức hỗ trợ quá trình phân tích log.
        
        Thuộc tính:
        -------------
            - `rex`       : Biểu thức chính quy được sử dụng cho quá trình tiền xử lý (step1). Mặc định: []
            - `path`      : Đường dẫn file log đầu vào 
            - `depth`     : Độ sâu của tất cả các Node lá (leaf node). Mặc định: 4 --> 4-2 = 2
            - `st`        : Ngưỡng tương đồng (similarity threshold). Mặc định: 0.4
            - `maxChild`  : Số lượng tối đa của các node con của một node nội tại (internal node - là một nút trong cây có ít nhất một node con). Mặc định: 100
            - `logName`   : Tên file đầu vào chứa các thông điệp raw log.
            - `savePath`  : Đường dẫn  file đầu ra chứa các log đã được cấu trúc.
            - `keep_para` : Yêu cầu có lưu giữ tham số hay không. Mặc định: true
            - `df_log`    : DataFrame lưu giữ quá trình phân tích log
            - `log_format`: Định dạng của một thông điệp raw log. Ex: '<Date> <Time> <Pid> <Level> <Component>: <Content>'
            
        Phương thức:
        ------------
            - `hasNumbers(self, s)`                     : Phương thức kiểm tra chuỗi đầu vào có chứa ít nhất một ký tự là chữ số hay không
            - `treeSearch(self, rn, seq)`               : Phương thức thực hiện tìm kiếm nhóm log phù hợp với Template "seq" đang xét, bắt đầu từ RootNode. Kết quả trả về là nhóm log phù hợp với template "seq" cho trước hoặc None nếu không tìm thấy
            - `addSeqToPrefixTree(self, rn, logClust)`  : Phương thức thực hiện thêm nhóm log "logClust" cho trước vào một internal Node phù hợp
            - `seqDist(self, seq1, seq2)`               : Phương thức thực hiện tính toán độ tương đồng của 02 template cho trước
            - `fastMatch(self, logClustL, seq)`         : Phương thức thực hiện tìm kiếm nhóm log phù hợp với "seq" cho trước dựa trên mảng các nhóm log "logClustL". Nếu độ tương đồng cao hơn ngưỡng cho phép thì mới trả về, nếu không, trả về None
            - `getTemplate(self, seq1, seq2)`           : Phương thức thực hiện đồng nhất giữa 02 template với nhau, những token khác nhau được thay thế bằng dấu <*>
            - `outputResult(self, logClustL)`           : Thực hiện in thông tin kết quả ra ngoài sau khi hoàn thành quá trình phân tích
            - `printTree(self, node, dep)`              : Phương thức thực hiện in ra cấu trúc của cây phân tích.
            - `parse(self, logName)`                    : Phương thức thực hiện quá trình phân tích log
            - `load_data(self)`                         : Phương thức nạp dữ liệu đầu vào để xử lý
            - `preprocess(self, line)`    : Tiền xử lý thông điệp log ban đầu thành các template. Phương thức chuyển đổi các message log thành template dựa trên các biểu thức chính quy cung cấp trong `seft.rex`.
            - `log_to_dataframe(self, log_file, regex, headers, logformat)`: Phương thức sử dụng để chuyển đổi các message log thành một DataFrame dựa trên các cột cho trước trong headers.
            - `generate_logformat_regex(self,logformat)`: Phương thức tạo biểu thức chính quy để phân tích log messages và tạo ra danh sách tên của các cột dựa trên đầu vào cho trước.
            - `get_parameter_list(self, row)`           : Phương thức được sử dụng để chuyển trích xuất các tham số có trong chuỗi message log. 
        """
    def __init__(
        self,
        log_format,
        indir="./",
        outdir="./result/",
        depth=4,
        st=0.4,
        maxChild=100,
        rex=[],
        keep_para=True,
    ):
        self.path = indir
        self.depth = depth - 2
        self.st = st
        self.maxChild = maxChild
        self.logName = None
        self.savePath = outdir
        self.df_log = None
        self.log_format = log_format
        self.rex = rex
        self.keep_para = keep_para

    def hasNumbers(self, s):
        """
        Phương thức kiểm tra chuỗi đầu vào có chứa ít nhất một ký tự là chữ số hay không

        Tham số:
            - `s` (_string_): Chuỗi đầu vào cần kiểm tra

        Trả về:
            _bool_: Kết quả `true` nếu chuỗi đó có ít nhất 1 ký tự là chữ số (0 - 9), ngược lại: `false`
        """
        return any(char.isdigit() for char in s)

    def treeSearch(self, rn, seq):
        """
        Phương thức thực hiện tìm kiếm nhóm log phù hợp với Template "seq" đang xét, bắt đầu từ RootNode. Kết quả trả về là nhóm log phù hợp với template "seq" cho trước hoặc None nếu không tìm thấy

        Tham số:
            - `rn`  : Root Node
            - `seq` : Template để thực hiện tìm kiếm nhóm log so khớp

        Returns:
            Nhóm log phù hợp || None
        """
        
        # Đầu tiên, kiểm tra độ dài, tiếp theo, duyệt từng token của template, kiểm tra token có trong Node cha không, nếu không thì kiểm tra tại token đặc biệt "<*>" 
        
        retLogClust = None

        seqLen = len(seq)
        if seqLen not in rn.childD:
            return retLogClust
        parentn = rn.childD[seqLen]

        currentDepth = 1
        for token in seq:
            if currentDepth >= self.depth or currentDepth > seqLen:
                break

            if token in parentn.childD:
                parentn = parentn.childD[token]
            elif "<*>" in parentn.childD:
                parentn = parentn.childD["<*>"]
            else:
                return retLogClust
            currentDepth += 1

        logClustL = parentn.childD

        retLogClust = self.fastMatch(logClustL, seq)

        return retLogClust

    def addSeqToPrefixTree(self, rn, logClust):
        """
        Phương thức thực hiện thêm nhóm log "logClust" cho trước vào một internal Node phù hợp

        Tham số:
            -`rn`: Đối tượng RootNode
            - `logClust`: Nhóm log cần thêm vào
        """
        
        # Ban đầu, kiểm tra độ dài của Template đã có trong RootNode chưa, nếu chưa thì thêm vào. Nếu có tiếp tục duyệt đến Internal Node tiếp theo để thêm vào.
        # Tiếp theo, duyệt từng token trong template log muốn thêm vào. Nếu token có trong Node, lấy Node cha hiện tại. Ngược lại, nếu không tồn tại, kiểm tra token có chữ số hay ko? Nếu có tồn tại ký tự chữ số trong token, thì lưu template vào Node đặc biệt <*>. Nếu không tồn tại ký tự chữ số trong token, nếu node cha đã có lượng node con tối đa, lưu template vào node đặc biệt <*>, nếu không, lưu template vào một node mới.
        seqLen = len(logClust.logTemplate)
        if seqLen not in rn.childD:
            firtLayerNode = Node(depth=1, digitOrtoken=seqLen)
            rn.childD[seqLen] = firtLayerNode   # Lưu giữ địa chỉ đối tượng.
        else:
            firtLayerNode = rn.childD[seqLen]   # Lấy địa chỉ Node con lớp 1

        parentn = firtLayerNode

        currentDepth = 1
        for token in logClust.logTemplate:
            # Thêm sự kiện log hiện tại vào Node leaf
            if currentDepth >= self.depth or currentDepth > seqLen:
                if len(parentn.childD) == 0:
                    parentn.childD = [logClust]
                else:
                    parentn.childD.append(logClust)
                break
            
            # Nếu token không nằm trong các layer đang tồn tại trong tree:
            if token not in parentn.childD:
                if not self.hasNumbers(token):
                    if "<*>" in parentn.childD:
                        if len(parentn.childD) < self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        else:
                            parentn = parentn.childD["<*>"]
                    else:
                        if len(parentn.childD) + 1 < self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken=token)
                            parentn.childD[token] = newNode
                            parentn = newNode
                        elif len(parentn.childD) + 1 == self.maxChild:
                            newNode = Node(depth=currentDepth + 1, digitOrtoken="<*>")
                            parentn.childD["<*>"] = newNode
                            parentn = newNode
                        else:
                            parentn = parentn.childD["<*>"]

                else:
                    if "<*>" not in parentn.childD:
                        newNode = Node(depth=currentDepth + 1, digitOrtoken="<*>")
                        parentn.childD["<*>"] = newNode
                        parentn = newNode
                    else:
                        parentn = parentn.childD["<*>"]

            # Nếu token có trong Node hiện tại
            else:
                parentn = parentn.childD[token]

            currentDepth += 1

    def seqDist(self, seq1, seq2): # seq1 is template: ["token1", "token2", ...]
        """
        Phương thức thực hiện tính toán độ tương đồng của 02 template cho trước

        Tham số:
            - `seq1`, `seq2` : 02 Template thực hiện so khớp độ tương đồng. Thông thường, `seq1` là template của các nhóm log, `seq2` là template log cần so khớp

        Trả về:
            - `retVal`  : Giá trị (float) tương đồng của 02 template 
            - `numOfPar`: Số lượng token tham số `<*>` có trong chuỗi `seq1`
        """
        assert len(seq1) == len(seq2) # Thông báo lỗi nếu 2 chuỗi không bằng nhau.
        simTokens = 0
        numOfPar = 0

        for token1, token2 in zip(seq1, seq2):
            if token1 == "<*>":
                numOfPar += 1
                continue
            if token1 == token2:
                simTokens += 1

        retVal = float(simTokens) / len(seq1)

        return retVal, numOfPar

    def fastMatch(self, logClustL, seq):
        """
        Phương thức thực hiện tìm kiếm nhóm log phù hợp với "seq" cho trước dựa trên mảng các nhóm log "logClustL". Nếu độ tương đồng cao hơn ngưỡng cho phép thì mới trả về, nếu không, trả về None 

        Tham số:
         - `logClustL`: Một LIST các nhóm log cho trước để tìm kiếm
         - `seq`      : Template log được dùng để so khớp

        Trả về:
            Nhóm log phù hợp nhất với "seq" || None
        """
        retLogClust = None

        maxSim = -1
        maxNumOfPara = -1
        maxClust = None

        for logClust in logClustL:
            curSim, curNumOfPara = self.seqDist(logClust.logTemplate, seq)
            # Ưu tiên với logClust có độ tương đồng cao nhất (1), có số lượng tham số nhiều hơn (2)
            if curSim > maxSim or (curSim == maxSim and curNumOfPara > maxNumOfPara): 
                maxSim = curSim
                maxNumOfPara = curNumOfPara
                maxClust = logClust

        if maxSim >= self.st: # Nếu độ tương đồng cao hơn ngưỡng cho phép thì mới trả về, nếu không, trả về None
            retLogClust = maxClust

        return retLogClust

    def getTemplate(self, seq1, seq2):
        """
        Phương thức thực hiện đồng nhất giữa 02 template với nhau, những token khác nhau được thay thế bằng dấu <*>

        Tham số:
            - `seq1`: Tham số đầu vào, thường là template log phù hợp với nhóm log đã tìm được
            - `seq2`: Tham số đầu vào, thường là template của nhóm log tìm được. Phương thức thực hiện để tìm ra template chung nhất để biểu diễn cho 2 template này.

        Trả về:
            Template chung nhất biểu diễn được cả 02 template trên
        """
        assert len(seq1) == len(seq2)
        retVal = []

        i = 0
        for word in seq1:
            if word == seq2[i]:
                retVal.append(word)
            else:
                retVal.append("<*>")

            i += 1

        return retVal

    def outputResult(self, logClustL):
        """
        Thực hiện in thông tin kết quả ra ngoài sau khi hoàn thành quá trình phân tích
        
        Tham số:
        --------
            - `logClustL`   : Danh sách các nhóm log đã thu thập được trong quá trình phân tách
        """
        log_templates = [0] * self.df_log.shape[0]
        log_templateids = [0] * self.df_log.shape[0]
        
        # Tạo ra một DataFrame df_event lưu giữ các giá trị template
        df_events = []
        for logClust in logClustL:
            template_str = " ".join(logClust.logTemplate)
            occurrence = len(logClust.logIDL)
            template_id = hashlib.md5(template_str.encode("utf-8")).hexdigest()[0:8]
            for logID in logClust.logIDL:
                logID -= 1
                log_templates[logID] = template_str
                log_templateids[logID] = template_id
            df_events.append([template_id, template_str, occurrence])

        # DataFrame lưu giữ các thông tin của Template
        df_event = pd.DataFrame(
            df_events, columns=["EventId", "EventTemplate", "Occurrences"]
        )
        
        self.df_log["EventId"] = log_templateids
        self.df_log["EventTemplate"] = log_templates
        if self.keep_para:
            self.df_log["ParameterList"] = self.df_log.apply(
                self.get_parameter_list, axis=1
            )
        self.df_log.to_csv(
            os.path.join(self.savePath, self.logName + "_structured.csv"), index=False
        )

        occ_dict = dict(self.df_log["EventTemplate"].value_counts())
        df_event = pd.DataFrame()
        df_event["EventTemplate"] = self.df_log["EventTemplate"].unique()
        df_event["EventId"] = df_event["EventTemplate"].map(
            lambda x: hashlib.md5(x.encode("utf-8")).hexdigest()[0:8]
        )
        df_event["Occurrences"] = df_event["EventTemplate"].map(occ_dict)
        df_event.to_csv(
            os.path.join(self.savePath, self.logName + "_templates.csv"),
            index=False,
            columns=["EventId", "EventTemplate", "Occurrences"],
        )

    def printTree(self, node, dep):
        """
        Phương thức thực hiện in ra cấu trúc của cây phân tích.
        
        Tham số: 
        --------
            - `node`: Root node
            - `dep` : Độ sâu của cây muốn in ra
        """
        pStr = ""
        for i in range(dep):
            pStr += "\t"

        if node.depth == 0:
            pStr += "Root"
        elif node.depth == 1:
            pStr += "<" + str(node.digitOrtoken) + ">"
        else:
            pStr += node.digitOrtoken

        print(pStr)

        if node.depth == self.depth:
            return 1
        for child in node.childD:
            self.printTree(node.childD[child], dep + 1)

    def parse(self, logName):
        """
        Phương thức thực hiện quá trình phân tích log
        
        Tham số: 
        --------
            - `logName`: Tên file đầu vào thực hiện phân tích
        """
        print("Parsing file: " + os.path.join(self.path, logName))
        start_time = datetime.now()
        self.logName = logName
        rootNode = Node() # Ban đầu, Root Node được khởi tạo.
        logCluL = []

        self.load_data() # Thực hiện nạp dữ liệu vào biến DataFrame: df_log

        count = 0
        for idx, line in self.df_log.iterrows(): # Lấy chỉ mục và dữ liệu của từng hàng tương ứng trong DataFrame
            logID = line["LineId"]
            logmessageL = self.preprocess(line["Content"]).strip().split()  # => Chuyển thông điệp log thành template
            matchCluster = self.treeSearch(rootNode, logmessageL)           # Kiểm tra xem có nhóm log nòa chứa template này không? 

            # Nếu không tồn tại nhóm log chứa template log này, tạo mới một nhóm log mới, sau đó thêm nhóm log mới vào List nhóm log và thực hiện thêm nhóm log này vào cây phân tích
            if matchCluster is None:
                newCluster = Logcluster(logTemplate=logmessageL, logIDL=[logID])
                logCluL.append(newCluster)
                self.addSeqToPrefixTree(rootNode, newCluster)

            # Ngược lại, nếu tồn tại nhóm log chứa template log này, thực hiện lấy template chung mới nhất, sau đó thêm index thông điệp vào nhóm log, đồng thời thực hiện đổi mới template của nhóm log này
            # Add the new log message to the existing cluster
            else:
                newTemplate = self.getTemplate(logmessageL, matchCluster.logTemplate)
                matchCluster.logIDL.append(logID)
                if " ".join(newTemplate) != " ".join(matchCluster.logTemplate):
                    matchCluster.logTemplate = newTemplate

            count += 1
            # Phần này để kiểm tra việc đọc log đến đâu? không có ý nghĩa quan trọng trong quá trình phân tích
            if count % 1000 == 0 or count == len(self.df_log):
                print(
                    "Processed {0:.1f}% of log lines.".format(
                        count * 100.0 / len(self.df_log)
                    )
                )

        if not os.path.exists(self.savePath):
            os.makedirs(self.savePath)

        self.outputResult(logCluL)

        print("Parsing done. [Time taken: {!s}]".format(datetime.now() - start_time))

    def load_data(self):
        """
        Phương thức nạp dữ liệu đầu vào để xử lý.
        """
        headers, regex = self.generate_logformat_regex(self.log_format)
        self.df_log = self.log_to_dataframe(
            os.path.join(self.path, self.logName), regex, headers, self.log_format
        )

    def preprocess(self, line):
        """
        Tiền xử lý thông điệp log ban đầu thành các template.
        Phương thức chuyển đổi các message log thành template dựa trên các biểu thức chính quy cung cấp trong `seft.rex`.

        Tham số:
        ------
            line: Message log cần chuyển đổi

        Trả về:
        -------
            Chuỗi đã được chuyển đổi
        """
        for currentRex in self.rex:
            line = re.sub(currentRex, "<*>", line)
        return line

    def log_to_dataframe(self, log_file, regex, headers, logformat):
        """
        Phương thức sử dụng để chuyển đổi các message log thành một DataFrame dựa trên các cột cho trước trong headers.

        Tham số:
        --------
            - `log_file`: File đầu vào chứa các message log
            - `regex`: Biểu thức chính quy được sử dụng để tìm log phù hợp
            - `headers`: Danh sách các tên cột mà ta muốn trích xuất từ dữ liệu log
            - `logformat`: Định dạng mong muốn cho log 
            
        Trả về:
        --------
            `logdf`: là một DataFrame đã được chuyển đổi.
        """
        log_messages = []
        linecount = 0
        with open(log_file, "r") as fin:
            for line in fin.readlines():
                try:
                    match = regex.search(line.strip())
                    message = [match.group(header) for header in headers]
                    log_messages.append(message)
                    linecount += 1
                except Exception as e:
                    print("[Warning] Skip line: " + line)
        logdf = pd.DataFrame(log_messages, columns=headers)
        logdf.insert(0, "LineId", None)
        logdf["LineId"] = [i + 1 for i in range(linecount)]
        print("Total lines: ", len(logdf))
        return logdf

    def generate_logformat_regex(self, logformat):
        """
        Phương thức tạo biểu thức chính quy để phân tích log messages và tạo ra danh sách tên của các cột dựa trên đầu vào cho trước.
        
        Tham số:
        ------------
        - `logformat`: Các tên cột cho trước cần có trong một log message
        
        Trả về:
        - `headers`: Danh sách tên các cột sử dụng trong DataFrame.
        - `regex`: Biểu thức chính quy được sử dụng để phân tích các log message.        
        """
        headers = []
        splitters = re.split(r"(<[^<>]+>)", logformat)
        regex = ""
        for k in range(len(splitters)):
            if k % 2 == 0:
                splitter = re.sub(" +", "\\\s+", splitters[k])
                regex += splitter
            else:
                header = splitters[k].strip("<").strip(">")
                regex += "(?P<%s>.*?)" % header
                headers.append(header)
        regex = re.compile("^" + regex + "$")
        return headers, regex

    def get_parameter_list(self, row):
        """
        Phương thức được sử dụng để chuyển trích xuất các tham số có trong chuỗi message log. 

        Tham số:
        -------
            `row` : Tham số là một đối tượng, yêu cầu có ít nhất 2 thuộc tính `EventTemplate` và `Content`. Trong thuộc tính EventTemplate, <***> chỉ có nhiều nhất 5 kí tự.

        Returns:
            Danh sách các tham số có trong chuỗi
        """
        template_regex = re.sub(r"<.{1,5}>", "<*>", row["EventTemplate"])
        if "<*>" not in template_regex:
            return []
        template_regex = re.sub(r"([^A-Za-z0-9])", r"\\\1", template_regex)
        template_regex = re.sub(r"\\ +", r"\\s+", template_regex)
        template_regex = "^" + template_regex.replace("\<\*\>", "(.*?)") + "$"
        parameter_list = re.findall(template_regex, row["Content"])
        parameter_list = parameter_list[0] if parameter_list else ()
        parameter_list = (
            list(parameter_list)
            if isinstance(parameter_list, tuple)
            else [parameter_list]
        )
        return parameter_list
