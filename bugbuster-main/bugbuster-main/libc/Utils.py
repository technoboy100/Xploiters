from os import scandir
import os

def SuperWrapper()->list:
    list = []
    filetypes = [".java",".py",".xml"]
    def Recursive(path:str)->list:
        data = scandir(path)
        for i in data:
            if i.is_dir():
                Recursive(i.path)
            else:
                if (any([j in i.path for j in filetypes])):
                    list.append(i.path)
    Recursive(os.getcwd())
    return list

print(SuperWrapper())