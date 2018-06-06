'''
text.py
ALl the text related method required for COMPSYS302 python project.
author : "iryu815"
'''

#turns common string to unicode
def emojify(string):
    temp = string
    temp = temp.replace("<3", u"\u2764")
    temp = temp.replace(":)", u"\u263a")
    temp = temp.replace(":D", u"\U0001f600")
    temp = temp.replace(":(", u"\u2639")
    temp = temp.replace(":s", u"\U0001f615")
    temp = temp.replace(":p", u"\U0001f61b")
    return temp

#html escape/ this avoids the html tags to run
html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }

def html_escape(text):
    return "".join(html_escape_table.get(c,c) for c in text)
