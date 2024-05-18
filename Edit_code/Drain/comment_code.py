# class Logcluster2(Logcluster):
#     """
#     Class được chỉnh sửa lại, bao gồm một số thông số như sau:
    
#     Thuộc tính:
#     ----------
#         - `logTemplate`     : Template đặc trưng đại diện cho nhóm log đó, ["The1", "the2", ...]
#         - `logIDL`          : Danh sách các ID message log thuộc nhóm log trên, [1,2,3,4,5, ...] 
#         - `logLevel`        : Danh sách các Level (INFO, WARN, FATAL, ERROR) mà nhóm log có thể biểu diễn, ["WARN", "INFO", ...]
#         - `logIDLevelL`     : Danh sách các ID message log thuộc level nào, {"WARN": [1,2,...], }
#         - `totalOccurrences`: Tổng số lần xảy ra của các Template tùy thuộc vào từng level {"INFO": 22, ...} 
#     """
#     def __init__(self, logTemplate="", logLevel="", logIDL=None):
#         self.logTemplate = logTemplate
#         self.logLevel = [logLevel]
#         if logIDL is None:
#             logIDL = []
#         self.logIDL = logIDL
#         self.logIDLevelL = {logLevel:list(logIDL)}
#         self.totalOccurrences = {}
        
#     def addIDLevel(self, logLevel, id):
#         if logLevel not in self.logLevel:
#             self.logLevel.append(logLevel)
#             self.logIDLevelL[logLevel] = [id]
#         else:
#             self.logIDLevelL[logLevel].append(id)
        
#     # Phương thức để đặt lại giá trị logLevel, logIDL và logIDLevelL
#     def resetValues(self):
#         self.logLevel = []
#         self.logIDL = []
#         self.logIDLevelL = {}









