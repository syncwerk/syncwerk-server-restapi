import requests
import json
import hashlib
import string
import random
import urllib

from xml.etree import cElementTree as ElementTree

class BBBMeeting:
  DEBUG = False;

  API_PREFIX       = 'api/'
  CREATE_MAX_RETRY = 5

  ACTION_TEST      = ''
  ACTION_CREATE    = 'create'
  ACTION_JOIN      = 'join'
  ACTION_END       = 'end'
  ACTION_GET_INFO  = 'getMeetingInfo'
  ACTION_GET_REC   = 'getRecordings'
  ACTION_DEL_REC   = 'deleteRecordings'
  ACTION_PUBLISH_REC = 'publishRecordings'


  TEST_SUCCESS     = 'SUCCESS'

  RESPONSE_RETURN_CODE_KEY = 'returncode'

  MESSAGE_KEY_MEETING_NAME_DUPLICATED = 'duplicateWarning'

  __server_url = None
  __secret     = None
  __meeting    = None
  __instance   = None
  __liveStreamToken = None
  __liveStreamServer = None

  @staticmethod 
  def getInstance(server_url = None, secret = None):
    if BBBMeeting.__instance == None:
      BBBMeeting.__instance = BBBMeeting(server_url, secret)
    return BBBMeeting.__instance

  def __init__(self, server_url = None, secret = None):
    self.setServerURL(server_url).setSecret(secret)

  def setServerURL(self, server_url):
    self.__server_url = server_url
    return self

  def getServerURL(self):
    return self.__server_url

  def setSecret(self, secret):
    self.__secret = secret
    return self

  def setLiveStreamToken(self, token):
    self.__liveStreamToken = token
    return self

  def setLiveStreamServer(self, server):
    self.__liveStreamServer = server
    return self

  def getLiveStreamToken(self):
    return self.__liveStreamToken

  def getLiveStreamServer(self):
    return self.__liveStreamServer

  def testConnection(self):
    try:
      response = self.__get(self.ACTION_TEST, '')
      return self.__BBBResponseValidate(response)

    except Exception:
      return False
  
  def createNewBBBMeeting(self, params, xml=''):
    """
      create new meeting on BBB server

      params: {
        'name': '', 
        'attendeePW': '', 
        'moderatorPW': '',
        'n': ''
        ... more params
      }

      we will create new meeting,
      then check if the meetingID is existed
      if existed we will regenerate the meetingID
      and try to recreate new meeting
    """
    # send the create new meeting request
    response = self.__post(
      self.ACTION_CREATE,
      self.__generateBBBRequest(params),
      xml
    )

    return self.__BBBResponseValidate(response)

  def joinMeeting(self, params):
    """
      Join a meeting,
      This return will contain a meeting URL you should redirect user to

      params = {
        'fullName' : (String) The full name that is to be used to identify this user to other conference attendees., 
        'meetingID': (String) The meeting's ID,
        'password' : (String) Password to join the meeting, could be mod or user  
      }

      Return values:
        - If join successful, Return the url to redirect
        - If failed, Return false
    """
    join_result = False
    params['redirect'] = 'true'
    meeting_info = self.getBBBMeetingInfo(params['meetingID'])
    if meeting_info == False:
      join_result = False
    elif meeting_info['returncode'] == self.TEST_SUCCESS:
      join_result = self.__getNewRequestURL(
        self.ACTION_JOIN,
        self.__generateBBBRequest(params)
      )

    return join_result

  def endMeeting(self, meeting_id, moderator_password):
    response = self.__get(
      self.ACTION_END,
      self.__generateBBBRequest({
        'meetingID': meeting_id,
        'password': moderator_password
      })
    )
    
    return self.__BBBResponseValidate(response)

  def getBBBMeetingInfo(self, meeting_id):
    response = self.__get(
      self.ACTION_GET_INFO,
      self.__generateBBBRequest({'meetingID': meeting_id})
    )

    return self.__BBBResponseValidate(response)

  def getBBBRecordings(self, request_dict):
    '''
      getBBBRecordings("meeting_id_1[, meeting_id_2[, meeting_id_n[, ...]]]")
      return records info of meeting_id(s) input
    '''
    response = self.__get(
      self.ACTION_GET_REC,
      self.__generateBBBRequest(request_dict)
    )
    return self.__BBBResponseValidate(response)

  def deleteBBBRecordings(self, recording_list_str):
    '''
      deleteBBBRecordings("recording_id1,recording_id2,recording_id_n,....")
      delete recordings from syste,
    '''
    response = self.__get(
      self.ACTION_DEL_REC,
      self.__generateBBBRequest({"recordID": recording_list_str })
    )

    return self.__BBBResponseValidate(response)
  
  def deleteBBBRecordings(self, recording_list_str):
    '''
      deleteBBBRecordings("recording_id1,recording_id2,recording_id_n,....")
      delete recordings from syste,
    '''
    response = self.__get(
      self.ACTION_DEL_REC,
      self.__generateBBBRequest({"recordID": recording_list_str })
    )

    return self.__BBBResponseValidate(response)

  def publishBBBRecordings(self, recording_list_str):
    '''
      deleteBBBRecordings("recording_id1,recording_id2,recording_id_n,....")
      delete recordings from syste,
    '''
    response = self.__get(
      self.ACTION_PUBLISH_REC,
      self.__generateBBBRequest({"recordID": recording_list_str, "publish": "true" })
    )

    return self.__BBBResponseValidate(response)
  
  def unpublishBBBRecordings(self, recording_list_str):
    '''
      deleteBBBRecordings("recording_id1,recording_id2,recording_id_n,....")
      delete recordings from syste,
    '''
    response = self.__get(
      self.ACTION_PUBLISH_REC,
      self.__generateBBBRequest({"recordID": recording_list_str, "publish": "false" })
    )

    return self.__BBBResponseValidate(response)

    


  ##########################################################################################
  #
  #  private methods
  #
  ##########################################################################################

  def __BBBResponseValidate(self, response):
    if response == False:
      return False
    validate_result = False
    return_code = self.RESPONSE_RETURN_CODE_KEY
    if return_code in response and response[return_code] == self.TEST_SUCCESS:
      validate_result = response
    
    return validate_result

  def __generateBBBRequest(self, params):
    return urllib.urlencode(params)

  def __post(self, action, request, xml="<?xml version='1.0' encoding='UTF-8'?><modules>	<module name='presentation'> <document url='https://scholar.harvard.edu/files/torman_personal/files/samplepptx.pptx' /> </module></modules>"):
    """Implement post method to the api"""
    try:
      response = False
      if self.__checkServerParams():
        request_url = self.__getNewRequestURL(action, request)

        if self.DEBUG: print(request_url)

        response = requests.post(request_url, xml)
        # TODO: check response data/code/header etc ...
        # then return the tree if request return ok
        if self.DEBUG: print(response.text)

      return self.__BBBResponseParse(response)
    except Exception:
      return False

  def __get(self, action, request):
    """Implement get method to the api"""
    try:
      response = False
      if self.__checkServerParams():
        request_url = self.__getNewRequestURL(action, request)

        if self.DEBUG: print(request_url)

        response = requests.get(request_url)
        # TODO: check response data/code/header etc ...
        # then return the tree if request return ok
        if self.DEBUG: print(response.text)

      return self.__BBBResponseParse(response)
    except Exception:
      return False

  def __BBBResponseParse(self, response):
    response = ElementTree.XML(response.text)
    xmldict=XmlDictConfig(response)
    if self.DEBUG: print xmldict
    return xmldict

  def __getNewChecksum(self, action, query):
    string_to_hash = action + query + self.__secret
    if self.DEBUG:
      print('string to hash: ' + string_to_hash)
      print('hashed request: ' + hashlib.sha1(string_to_hash).hexdigest())

    return hashlib.sha1(string_to_hash).hexdigest()

  def __getNewRequestURL(self, action, request):
    checksum = self.__getNewChecksum(action, request)
    request_url = self.__server_url + self.API_PREFIX
    if action is not None and request is not None:
      request_url = request_url + action + '?' + request + '&checksum=' + checksum
    
    return request_url    

  def __checkServerParams(self):
    check = True
    if (self.__server_url is None) or (self.__secret is None):
      check = False
    return check

  # self tests
  def selfTest(self):
    b3 = BBBMeeting.getInstance(
        '', '')

    params = {
      'name'       : 'test_meeting',
      'meetingID'  : '',
      'attendeePW' : 'nap',
      'moderatorPW': 'nap',
      'fullName'   : 'Test User'
    }

    print('###################################')
    print('test the get recording')
    b3.getBBBRecordings('syncwerk-6226dce7-3dce-415f-a1fc-6a7839b3dea0')

    print('###################################')
    print('test the connect')
    if b3.testConnection(): 
      print('TEST: Connection OK') 
    else: 
      print('TEST: Connection Failed')
      return False

    print('')
    print('###################################')
    print('test create new BBBMeeting')
    create_result = b3.createNewBBBMeeting(params)
    if create_result['returncode'] == self.TEST_SUCCESS:
        print('TEST: Create room OK')
    else:
      print('TEST: Create room Failed')
      return False

    print('')
    print('###################################')
    print('test get BBBMeeting info')
    info_result = b3.getBBBMeetingInfo(create_result['meetingID'])
    if info_result['returncode'] == self.TEST_SUCCESS:
      print('TEST: get BBB info OK')
    else:
      print('TEST: get BBB info Failed')
      return False

    print('')
    print('###################################')
    print('test get BBBMeeting info WRONG MEETINGID')
    info_result = b3.getBBBMeetingInfo(create_result['meetingID'] + '___')
    if info_result == False:
      print('TEST: get BBB WRONG MEETINGID info OK')
    else:
      print('TEST: get BBB WRONG MEETINGID info Failed')
      return False

    print('')
    print('###################################')
    print('test get BBBMeeting moderator join')
    params['password'] = params['moderatorPW']
    params['meetingID'] = create_result['meetingID']
    m_join_result = b3.joinMeeting(params)
    print (m_join_result)

    print('')
    print('###################################')
    print('test get BBBMeeting end')
    end_result = b3.endMeeting(
      create_result['meetingID'], 
      params['attendeePW']
    )
    if end_result['returncode'] == self.TEST_SUCCESS:
      print('TEST: get end OK')
    else:
      print('TEST: get end Failed')
      return False


#####################################
class XmlListConfig(list):
    def __init__(self, aList):
        for element in aList:
            if element:
                # treat like dict
                if len(element) == 1 or element[0].tag != element[1].tag:
                    self.append(XmlDictConfig(element))
                # treat like list
                elif element[0].tag == element[1].tag:
                    self.append(XmlListConfig(element))
            elif element.text:
                text = element.text.strip()
                if text:
                    self.append(text)

####################################
class XmlDictConfig(dict):
    '''
    Example usage:

    >>> tree = ElementTree.parse('your_file.xml')
    >>> root = tree.getroot()
    >>> xmldict = XmlDictConfig(root)

    Or, if you want to use an XML string:

    >>> root = ElementTree.XML(xml_string)
    >>> xmldict = XmlDictConfig(root)

    And then use xmldict for what it is... a dict.
    '''

    def __init__(self, parent_element):
        if parent_element.items():
            self.update(dict(parent_element.items()))
        for element in parent_element:
            if element:
                # treat like dict - we assume that if the first two tags
                # in a series are different, then they are all different.
                if len(element) == 1 or element[0].tag != element[1].tag:
                    aDict = XmlDictConfig(element)
                # treat like list - we assume that if the first two tags
                # in a series are the same, then the rest are the same.
                else:
                    # here, we put the list in dictionary; the key is the
                    # tag name the list elements all share in common, and
                    # the value is the list itself
                    aDict = {element[0].tag: XmlListConfig(element)}
                # if the tag has attributes, add those to the dict
                if element.items():
                    aDict.update(dict(element.items()))
                self.update({element.tag: aDict})
            # this assumes that if you've got an attribute in a tag,
            # you won't be having any text. This may or may not be a
            # good idea -- time will tell. It works for the way we are
            # currently doing XML configuration files...
            elif element.items():
                self.update({element.tag: dict(element.items())})
            # finally, if there are no child tags and no attributes, extract
            # the text
            else:
                self.update({element.tag: element.text})

############################
#BBBMeeting().selfTest()
