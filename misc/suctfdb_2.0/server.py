#!/usr/bin/python

import suctfdb
import numpy as np
import sys

db = None

def menu():
    print "1. Create DB"
    print "2. Edit DB specs"
    print "3. Print DB info"
    print "4. Delete DB"
    print "5. Run method"
    print "6. Exit"


def create_db():
    global db
    cid = int(raw_input("Enter id: "))
    tag = raw_input("Enter tag: ")
    len = int(raw_input("Enter len: "))
    db = suctfdb.DB(len, cid, tag)
    if db:
        print "DB craeted successfully"
        print hex(id(db))

def delete_db():
    global db
    del db
    db = None
    print "DB deleted successfully"

def edit_db():
    print "Which one to edit: "
    print "\t- [1] tag"
    print "\t- [2] seq"
    se = int(raw_input("Enter code: "))
    if se == 1:
        tag = raw_input("Enter new tag: ")
        db.set_tag(tag)
    elif se == 2:
        t = int(raw_input("Enter 1 for np.array, 0 otherwise: "))
        seq = raw_input("Enter new seq: ")
        if t == 1:
            db.set_seq(np.array(np.mat(seq)), 1)
            #print db.get_seq()
        else:
            db.set_seq(seq, 0)
    print "edit_db done"

def print_db():
    print "t", db.get_seq()
    print "Which one to print: "
    print "\t- [1] tag"
    print "\t- [2] seq"
    
    se = int(raw_input("Enter code: "))
    print "DB->"
    print "\tid:", db.get_id()
    if se == 1:
        print "\ttag:", db.get_tag()
    elif se == 2:
        print "\tseq:", db.get_seq()



def main():

    print "WELCOME TO SUCTF SEQ HOLDER"
    while True:
        menu()
        try:
            i = int(raw_input("Enter selected menu> "))
            if i == 1:
                create_db()
            elif i == 2:
                edit_db()
            elif i == 3:
                print_db()
            elif i == 4:
                delete_db()
            elif i == 5:
                print db.call_method()
            elif i == 6:
                break
            else:
                continue
        except Exception as e:
            #print "exc", e
            pass

    print "Good bye"
    return 0



if __name__ == '__main__':
    sys.exit(main())
