import boto3
import requests
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .cognito_service import CognitoService
from .decorators import cognito_authentication_required
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.conditions import Attr

cognito_service = CognitoService()

class SignUp(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')
        if not username or not password or not email:
            return Response({'success': False, 'error': 'Missing username, password or email'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            response = cognito_service.sign_up(username, password, email)
            # Create a new entry in DynamoDB
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('EventSphereUsers')
            table.put_item(
                Item={
                    'username': username,
                    'email': email,
                    'friends': [],
                    'friendRequests': [],
                    'inbox': [],
                    'createdEvents': [],
                    'pendingEvents': [],
                    'acceptedEvents': [],
                    'declinedEvents': [],
                    'profilepic': '',
                    'newUser': 'true'
                }
            )

            # Create a new entry in Public DynamoDB
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('EventSpherePublicUsers')
            table.put_item(
                Item={
                    'username': username,
                    'inbox': [],
                    'name': '',
                    'profilepic': '',
                }
            )
            return Response({'success': True}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Verify(APIView):  
    def post(self, request):
        username = request.data.get('username')
        code = request.data.get('code')

        if not username or not code:
            return Response({'success': False, 'error': 'Missing username or code'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            response = cognito_service.confirm_sign_up(username, code)
            return Response({'success': True})
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SignIn(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return Response({'success': False, 'error': 'Missing username or password'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            response = cognito_service.authenticate_user(username, password)
            return Response({'success': True, 'data': response})
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SignOut(APIView):
    def post(self, request):
        access_token = request.data.get('accesstoken')
        if not access_token:
            return Response({'success': False, 'error': 'Missing access token'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            response = cognito_service.sign_out(access_token)
            return Response({'success': True})
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RetrieveUserData(APIView):
    @cognito_authentication_required
    def get(self, request):
        username = request.GET.get('username')
        if not username:
            return Response({"error": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not hasattr(request, 'user_info'):
            return Response({"error": "Unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Retrieve user data from DynamoDB Index with username as the key
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('EventSphereUsers')
        inbox = dynamodb.Table('EventSpherePublicUsers')

        try:
            response = table.get_item(
                Key={
                    'username': username
                }
            )
            item = response.get('Item', None)
            if not item:
                return Response({"success": False, "error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
            response = inbox.get_item(
                Key={
                    'username': username
                }
            )
            userInbox = response.get('Item', None)

            return Response({"success": True, "userData": item, 'userInbox': userInbox}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class EditUser(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

        name = request.data.get('name')
        username = request.data.get('username')
        email = request.data.get('email')
        profilepic = request.data.get('profilepic')
        createdEvents = request.data.get('createdEvents')
        pendingEvents = request.data.get('pendingEvents')
        acceptedEvents = request.data.get('acceptedEvents')
        declinedEvents = request.data.get('declinedEvents')
        friends = request.data.get('friends')
        inbox = request.data.get('inbox')
        friendRequests = request.data.get('friendRequests')
        newUser = "false"


        dynamodb = boto3.resource(
            'dynamodb', 
            region_name='us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        table = dynamodb.Table('EventSphereUsers') 
        publicTable = dynamodb.Table('EventSpherePublicUsers')
        try:
            table.update_item(
                Key={
                    'username': username
                },
                UpdateExpression="set #n = :n, email = :e, profilepic = :p, createdEvents = :c, pendingEvents = :pe, acceptedEvents = :ae, declinedEvents = :de, friends = :f, newUser = :nu, inbox = :i, friendRequests = :r",
                ExpressionAttributeValues={
                    ':n': name,
                    ':e': email,
                    ':p': profilepic,
                    ':c': createdEvents,
                    ':pe': pendingEvents,
                    ':ae': acceptedEvents,
                    ':de': declinedEvents,
                    ':f': friends,
                    ':nu': newUser,
                    ':i': inbox,
                    ':r': friendRequests
                },
                ExpressionAttributeNames={
                    "#n": "name"
                }
            )
            publicTable.update_item(
                Key={
                    'username': username
                },
                UpdateExpression="set #n = :n, profilepic = :p",
                ExpressionAttributeValues={
                    ':n': name,
                    ':p': profilepic
                },
                ExpressionAttributeNames={
                    "#n": "name"
                }
            )
            return Response({"success": True, "message": "User data updated successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Adds newEvent From Request to User's createedEvents list in DynamoDB
class CreateEvent(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

        username = request.data.get('username')
        newEvent = request.data.get('newEvent')

        if not username or not newEvent:
            return Response({"success": False, "error": "username and newEvent are required"}, status=status.HTTP_400_BAD_REQUEST)

        dynamodb = boto3.resource(
            'dynamodb', 
            region_name='us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        table = dynamodb.Table('EventSphereUsers')
        try:
            response = table.get_item(Key={'username': username})
            item = response.get('Item')

            if not item:
                return Response({"success": False, "error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            createdEvents = item.get('createdEvents')
            if createdEvents is None or 'NULL' in createdEvents:
                createdEvents = []



            createdEvents.append(newEvent)

            table.update_item(
                Key={'username': username},
                UpdateExpression="SET createdEvents = :ce",
                ExpressionAttributeValues={':ce': createdEvents}
            )


            return Response({"success": True, "message": "Event added successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteEvent(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

        username = request.data.get('username')
        eventidToDelete = request.data.get('eventToDelete')

        if not username or not eventidToDelete:
            return Response({"success": False, "error": "username and eventidToDelete are required"}, status=status.HTTP_400_BAD_REQUEST)

        dynamodb = boto3.resource(
            'dynamodb', 
            region_name='us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        table = dynamodb.Table('EventSphereUsers')
        try:
            response = table.get_item(Key={'username': username})
            item = response.get('Item')

            if not item:
                return Response({"success": False, "error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            createdEvents = item.get('createdEvents')

            # Check if createdEvents is None or has the 'NULL' attribute set to True
            if createdEvents is None or 'NULL' in createdEvents:
                createdEvents = []

            # Find the event with the matching eventid in the createdEvents list
            eventToDelete = next((event for event in createdEvents if event['eventid'] == eventidToDelete), None)

            if eventToDelete:
                createdEvents.remove(eventToDelete)
            else:
                return Response({"success": False, "error": "Event not found in createdEvents"}, status=status.HTTP_404_NOT_FOUND)

            table.update_item(
                Key={'username': username},
                UpdateExpression="SET createdEvents = :ce",
                ExpressionAttributeValues={':ce': createdEvents}
            )

            return Response({"success": True, "message": "Event deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SearchPublicTable(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

        search_term = request.data.get('searchTerm')
        print(search_term)
        items = []

        if search_term == "":
            return Response({"success": True, "userData": items}, status=status.HTTP_200_OK)

        if not search_term:
            return Response({"success": False, "error": "searchTerm is required"}, status=status.HTTP_200_OK)

        dynamodb = boto3.resource(
            'dynamodb', 
            region_name='us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        table = dynamodb.Table('EventSpherePublicUsers')
        try:
            response = table.scan(
                FilterExpression=Attr('username').contains(search_term)
            )
            items = response.get('Items', [])

            if not items:
                items = []
                return Response({"success": True, "userData": items}, status=status.HTTP_200_OK)



            return Response({"success": True, "userData": items}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# request.from = username of the user sending the friend request
# request.to = username of the user receiving the friend request
# request.status = 'pending' or 'accepted' or 'declined'
# this view will add a friend request to the 'to' users public table 'inbox' list
# and add the friend request to the 'from' users 'friendRequests' list
# the 'status' will be set to 'pending' by default
class SendFriendRequest(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY

        fromUser = request.data.get('from')
        toUser = request.data.get('to')
        request_status = 'pending'

        if not fromUser or not toUser:
            return Response({"success": False, "error": "from and to are required"}, status=status.HTTP_200_OK)
        

        dynamodb = boto3.resource(
            'dynamodb', 
            region_name='us-east-1',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        toTable = dynamodb.Table('EventSpherePublicUsers')
        fromTable = dynamodb.Table('EventSphereUsers')
        try:
            response = toTable.get_item(Key={'username': toUser})
            item = response.get('Item')

            if not item:
                return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
            
            inbox = item.get('inbox')
            if inbox is None or 'NULL' in inbox:
                inbox = []
            
            inbox.append({
                'type': 'friendRequest',
                'from': fromUser,
                'status': request_status
            })

            toTable.update_item(
                Key={'username': toUser},
                UpdateExpression="SET inbox = :i",
                ExpressionAttributeValues={':i': inbox}
            )

            response = fromTable.get_item(Key={'username': fromUser})
            item = response.get('Item')

            if not item:
                return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
            
            friendRequests = item.get('friendRequests')
            if friendRequests is None or 'NULL' in friendRequests:
                friendRequests = []
            
            friendRequests.append({
                'to': toUser,
                'status': request_status
            })

            fromTable.update_item(
                Key={'username': fromUser},
                UpdateExpression="SET friendRequests = :f",
                ExpressionAttributeValues={':f': friendRequests}
            )


            return Response({"success": True, "message": "Friend request sent successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# This Class will be used to accept or decline a friend request
# request.from = username of the user deciding on the friend request
# request.to = username of the user who sent the friend request
# request.status = 'accepted' or 'declined'
# this view will update the 'to' users 'inbox' list to remove the friend request
# and update the 'from' users 'friendRequests' list to remove the friend request
# if the status is 'accepted' then the 'to' users 'friends' list will be updated with the 'from' user
# and the 'from' users 'friends' list will be updated with the 'to' user
# if the status is 'declined' then nothing will be updated in the 'friends' list

class DecideFriendRequest(APIView):
    def post(self, request):
        aws_access_key_id = settings.AWS_ACCESS_KEY_ID
        aws_secret_access_key = settings.AWS_SECRET_ACCESS_KEY
        fromUser = request.data.get('from') # Decider
        toUser = request.data.get('to')     # Decided

        request_status = request.data.get('status') # Accepted / Declined

        if not fromUser or not toUser or not status:
            return Response({"success": False, "error": "from, to, and status are required"}, status=status.HTTP_200_OK)
        
        if request_status != 'accepted' and request_status != 'declined':
            return Response({"success": False, "error": "status must be 'accepted' or 'declined'"}, status=status.HTTP_200_OK)
        
        if fromUser == toUser:
            return Response({"success": False, "error": "from and to cannot be the same"}, status=status.HTTP_200_OK)
        
        if request_status == 'accepted':
            # Add each user to the others friends list
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name='us-east-1',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            toTable = dynamodb.Table('EventSphereUsers')
            fromTable = dynamodb.Table('EventSphereUsers')
            try:
                response = toTable.get_item(Key={'username': toUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                friends = item.get('friends')
                if friends is None or 'NULL' in friends:
                    friends = []
                
                friends.append(fromUser)

                toTable.update_item(
                    Key={'username': toUser},
                    UpdateExpression="SET friends = :f",
                    ExpressionAttributeValues={':f': friends}
                )

                response = fromTable.get_item(Key={'username': fromUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                friends = item.get('friends')
                if friends is None or 'NULL' in friends:
                    friends = []
                
                friends.append(toUser)

                fromTable.update_item(
                    Key={'username': fromUser},
                    UpdateExpression="SET friends = :f",
                    ExpressionAttributeValues={':f': friends}
                )

            # Remove the friend Request from 'to' users friendRequests list
            # Remove the friend Request from 'from' users public inbox list
                dynamodb = boto3.resource(
                    'dynamodb', 
                    region_name='us-east-1',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
                toTable = dynamodb.Table('EventSpherePublicUsers')
                fromTable = dynamodb.Table('EventSphereUsers')

                response = toTable.get_item(Key={'username': toUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                inbox = item.get('inbox')
                if inbox is None or 'NULL' in inbox:
                    inbox = []
                
                inbox = [i for i in inbox if i['from'] != fromUser]

                toTable.update_item(
                    Key={'username': toUser},
                    UpdateExpression="SET inbox = :i",
                    ExpressionAttributeValues={':i': inbox}
                )

                response = fromTable.get_item(Key={'username': fromUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                friendRequests = item.get('friendRequests')
                if friendRequests is None or 'NULL' in friendRequests:
                    friendRequests = []
                
                friendRequests = [i for i in friendRequests if i['to'] != toUser]

                fromTable.update_item(
                    Key={'username': fromUser},
                    UpdateExpression="SET friendRequests = :f",
                    ExpressionAttributeValues={':f': friendRequests}
                )


                return Response({"success": True, "message": "Friend request accepted successfully"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Remove the friend Request from 'to' users friendRequests list
            # Remove the friend Request from 'from' users public inbox list
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name='us-east-1',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            toTable = dynamodb.Table('EventSpherePublicUsers')
            fromTable = dynamodb.Table('EventSphereUsers')

            try:
                response = toTable.get_item(Key={'username': toUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                inbox = item.get('inbox')
                if inbox is None or 'NULL' in inbox:
                    inbox = []
                
                inbox = [i for i in inbox if i['from'] != fromUser]

                toTable.update_item(
                    Key={'username': toUser},
                    UpdateExpression="SET inbox = :i",
                    ExpressionAttributeValues={':i': inbox}
                )

                response = fromTable.get_item(Key={'username': fromUser})
                item = response.get('Item')

                if not item:
                    return Response({"success": False, "error": "User not found"}, status=status.HTTP_200_OK)
                
                friendRequests = item.get('friendRequests')
                if friendRequests is None or 'NULL' in friendRequests:
                    friendRequests = []
                
                friendRequests = [i for i in friendRequests if i['to'] != toUser]

                fromTable.update_item(
                    Key={'username': fromUser},
                    UpdateExpression="SET friendRequests = :f",
                    ExpressionAttributeValues={':f': friendRequests}
                )

                return Response({"success": True, "message": "Friend request declined successfully"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"success": False, "error": f"An error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            


        

