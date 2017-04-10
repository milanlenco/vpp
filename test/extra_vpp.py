#!/usr/bin/env python

import os
import unittest
import inspect
from multiprocessing import Process, Pipe
from pickle import dumps, PicklingError
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.utils import rdpcap
from scapy.plist import PacketList
from framework import VppTestCase
from memif_pg_interface import VppPGInterface
from picklable_packet import PicklablePacket


class SerializableClassCopy(object):
    """
    Empty class used as a basis for a serializable copy of another class.
    """
    pass


class RemoteClassAttr(object):
    """
    Wrapper around attribute of a remotely executed class.
    """
    def __init__(self, remote, attr):
        self._path = [attr] if attr else []
        self._remote = remote

    def path_to_str(self):
        return '.'.join(self._path)

    def get_remote_value(self):
        return self._remote._remote_exec(RemoteClass.GET, self.path_to_str())

    def __repr__(self):
        return self._remote._remote_exec(RemoteClass.REPR, self.path_to_str())

    def __str__(self):
        return self._remote._remote_exec(RemoteClass.STR, self.path_to_str())

    def __getattr__(self, attr):
        if attr[0] == '_':
            raise AttributeError
        self._path.append(attr)
        return self

    def __setattr__(self, attr, val):
        if attr[0] == '_':
            super(RemoteClassAttr, self).__setattr__(attr, val)
            return
        self._path.append(attr)
        self._remote._remote_exec(RemoteClass.SETATTR, self.path_to_str(),
                True, value = val)

    def __call__(self, *args, **kwargs):
        return self._remote._remote_exec(RemoteClass.CALL, self.path_to_str(),
                True, *args, **kwargs)


class RemoteClass(Process):
    """
    This class can wrap around and adapt the interface of another class,
    and then delegate its execution to a newly forked child process.
    Usage:
        # Create a remotely executed instance of MyClass
        object = RemoteClass(MyClass, arg1='foo', arg2='bar')
        object.start_remote()
        # Access the object normally as if it was an instance of your class.
        object.my_attribute = 20
        print object.my_attribute
        print object.my_method(object.my_attribute)
        object.my_attribute.nested_attribute = 'test'
        # If you need the value of a remote attribute, use .get_remote_value
        method. This method is automatically called when needed in the context
        of a remotely executed class. E.g.:
        if (object.my_attribute.get_remote_value() > 20):
            object.my_attribute2 = object.my_attribute  # automatically obtained
        # Destroy the instance
        object.quit_remote()
        object.terminate()
    """

    GET = 0       # Get attribute remotely
    CALL = 1      # Call method remotely
    SETATTR = 2   # Set attribute remotely
    REPR = 3      # Get representation of a remote object
    STR = 4       # Get string representation of a remote object
    QUIT = 5      # Quit remote execution

    PIPE_PARENT = 0 # Parent end of the pipe
    PIPE_CHILD = 1  # Child end of the pipe

    DEFAULT_TIMEOUT = 2 # default timeout for an operation to execute

    def __init__(self, cls, *args, **kwargs):
        super(RemoteClass, self).__init__()
        self._cls = cls
        self._args = args
        self._kwargs = kwargs
        self._timeout = RemoteClass.DEFAULT_TIMEOUT
        self._pipe = Pipe() # pipe for input/output arguments

    def __repr__(self):
        return repr(RemoteClassAttr(self, None))

    def __str__(self):
        return str(RemoteClassAttr(self, None))

    def __call__(self, *args, **kwargs):
        return self.RemoteClassAttr(self, None)()

    def __getattr__(self, attr):
        if attr[0] == '_' or not self.is_alive():
            if hasattr(super(RemoteClass, self), '__getattr__'):
                return super(RemoteClass, self).__getattr__(attr)
            raise AttributeError
        return RemoteClassAttr(self, attr)

    def __setattr__(self, attr, val):
        if attr[0] == '_' or not self.is_alive():
            super(RemoteClass, self).__setattr__(attr, val)
            return
        setattr(RemoteClassAttr(self, None), attr, val)

    def _remote_exec(self, op, path=None, ret=True, *args, **kwargs):
        """
        Execute given operation on a given, possibly nested, member remotely.
        """
        # automatically resolve remote objects in the arguments
        mutable_args = list(args)
        for i,val in enumerate(mutable_args):
            if isinstance(val, RemoteClass) or isinstance(val, RemoteClassAttr):
                mutable_args[i] = val.get_remote_value()
        args = tuple(mutable_args)
        for key,val in kwargs.iteritems():
            if isinstance(val, RemoteClass) or isinstance(val, RemoteClassAttr):
                kwargs[key] = val.get_remote_value()
        # send request
	if args:
		if type(args[0]) is list:
			if type(args[0][0]) is Ether:
				l = []
				for p in args[0]:
					l.append(PicklablePacket(p))
				del args;
				args = (l,);
	self._pipe[RemoteClass.PIPE_PARENT].send((op, path, args, kwargs))
        if not ret:
            # no return value expected
            return None
        timeout = self._timeout
        # adjust timeout specifically for the .sleep method
        if path.split('.')[-1] == 'sleep':
            if args and isinstance(args[0], (long, int)):
                timeout += args[0]
            elif kwargs.has_key('timeout'):
                timeout += kwargs['timeout']
        if not self._pipe[RemoteClass.PIPE_PARENT].poll(timeout):
            return None
        try:
            rv = self._pipe[RemoteClass.PIPE_PARENT].recv()
            return rv
        except EOFError:
            return None

    def _get_local_object(self, path):
        """
        Follow the path to obtain a reference on the addressed nested attribute
        """
        obj = self._instance
        for attr in path:
            obj = getattr(obj, attr)
        return obj

    def _get_local_value(self, path):
        try:
            return self._get_local_object(path)
        except AttributeError:
            return None

    def _call_local_method(self, path, *args, **kwargs):
        try:
            method = self._get_local_object(path)
            return method(*args, **kwargs)
        except AttributeError:
            return None

    def _set_local_attr(self, path, value):
        try:
            obj = self._get_local_object(path[:-1])
            setattr(obj, path[-1], value)
        except AttributeError:
            pass
        return None

    def _get_local_repr(self, path):
        try:
            obj = self._get_local_object(path)
            return repr(obj)
        except AttributeError:
            return None

    def _get_local_str(self, path):
        try:
            obj = self._get_local_object(path)
            return str(obj)
        except AttributeError:
            return None

    def _serializable(self, obj):
        """ Test if the given object is serializable """
        try:
            dumps(obj)
            return True
        except:
            return False

    def _make_obj_serializable(self, obj):
        """
        Make a serializable copy of an object.
        Members which are difficult/impossible to serialize are stripped.
        """
        if self._serializable(obj):
            return obj # already serializable
        copy = SerializableClassCopy()
        # copy at least serializable attributes and properties
        for name, member in inspect.getmembers(obj):
            if name[0] == '_': # skip private members
                continue
            if callable(member) and not isinstance(member, property):
                continue
            if not self._serializable(member):
                continue
            setattr(copy, name, member)
        return copy

    def _make_serializable(self, obj):
        """
        Make a serializable copy of an object or a list/tuple of objects.
        Members which are difficult/impossible to serialize are stripped.
        """
        if (type(obj) is list) or (type(obj) is tuple) or (type(obj) is PacketList):
            rv = []
	    if (type(obj) is PacketList):
	        for p in obj:
		    rv.append(PicklablePacket(p))
	    else:
                for item in obj:
                    rv.append(self._make_serializable(item))
                if type(obj) is tuple:
                    rv = tuple(rv)
            return rv
        else:
            return self._make_obj_serializable(obj)

    def start_remote(self):
        """ Start remote execution """
        self.start()

    def quit_remote(self):
        """ Quit remote execution """
        self._remote_exec(RemoteClass.QUIT, None, False)

    def get_remote_value(self):
        """ Get value of a remotely held object """
        return RemoteClassAttr(self, None).get_remote_value()

    def set_request_timeout(self, timeout):
        """ Change request timeout """
        self._timeout = timeout

    def run(self):
        """
        Create instance of the wrapped class and execute operations
        on it as requested by the parent process.
        """
        self._instance = self._cls(*self._args, **self._kwargs)
        while True:
            try:
                rv = None
                # get request from the parent process
                (op, path, args, kwargs) = self._pipe[RemoteClass.PIPE_CHILD].recv()
                path = path.split('.') if path else []
                if op == RemoteClass.GET:
                    rv = self._get_local_value(path)
                elif op == RemoteClass.CALL:
                    rv = self._call_local_method(path, *args, **kwargs)
                elif op == RemoteClass.SETATTR and 'value' in kwargs:
                    self._set_local_attr(path, kwargs['value'])
                elif op == RemoteClass.REPR:
                    rv = self._get_local_repr(path)
                elif op == RemoteClass.STR:
                    rv = self._get_local_str(path)
                elif op == RemoteClass.QUIT:
                    break
                else:
                    continue
                # send return value
                if not self._serializable(rv):
                    rv = self._make_serializable(rv)
                self._pipe[RemoteClass.PIPE_CHILD].send(rv)
            except EOFError:
                break
        self._instance = None  # destroy the instance


@unittest.skip("No tests here!")
class ExtraVpp(VppTestCase):
    """ Re-use VppTestCase to create extra VPP instance """

    def __init__(self):
        super(ExtraVpp, self).__init__("emptyTest")

    def __del__(self):
        if hasattr(self, "vpp"):
            cls.vpp.poll()
            if cls.vpp.returncode is None:
                cls.vpp.terminate()
                cls.vpp.communicate()

	
    @classmethod
    def tearDownClass(cls):
	print('exptra_vpp.py tear down class')
        super(ExtraVpp, cls).tearDownClass()

    @classmethod
    def setUpClass(cls):
        # disable features unsupported in the extra VPP
        orig_env = dict(os.environ)
        if os.environ.has_key('STEP'):
            del os.environ['STEP']
        if os.environ.has_key('DEBUG'):
            del os.environ['DEBUG']
        super(ExtraVpp, cls).setUpClass()
        os.environ = orig_env

    @unittest.skip("Empty test used for initialization of extra VPP")
    def emptyTest(self):
        """ Do nothing """
        pass

    def setTestFunctionInfo(self, name, doc):
        """
        Store the name and documentation string of currently executed test
        in the main VPP for logging purposes.
        """
        self._testMethodName = name
	self._testMethodDoc = doc