from rest_framework import serializers
from netflix_rest_api_app.models import CustomUser



class CustomUserSerializer(serializers.ModelSerializer):
    
   # password2 = serializers.CharField(style = { 'input_type':'password'},write_only = True)
    class Meta:
        model = CustomUser
        fields = ['id','username','email','password']

        extra_kwargs = {
            'password': {'write_only': True}
        }
    def save(self):
        password = self.validated_data['password'] 
        print('came inside save func')
        if CustomUser.objects.filter(email=self.validated_data['email']).exists(): 
            raise serializers.ValidationError({'error': 'Email already exists!'})
        print('%%%%%%%%%%%%%%55')
        save_user = CustomUser(username=self.validated_data['username'],email=self.validated_data['email'] )
        print(save_user)
        save_user.set_password(password)  
        save_user.save()
        print('111111111111111111111111')
        print(save_user)
        return save_user