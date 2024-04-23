from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from .models import CustomUser,Whitelist, Blacklist,MessageSendInfo
from .emailsend import main_send

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'coins', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('email', 'username')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'coins', 'password')}),
        (_('Personal info'), {'fields': ('username',)}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'coins', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )
    
   
    def save_model(self, request, obj, form, change):
        # Get the original object from the database (if it exists)
        if change:
            orig_obj = self.model.objects.get(pk=obj.pk)
            # Check if certain fields have changed (e.g., email)
            if obj.email != orig_obj.email:
                new_mail=obj.email
                old_mail=orig_obj.email
                main_send(new_mail,old_mail)      
        # Save the object
        super().save_model(request, obj, form, change)

 

admin.site.register(CustomUser, CustomUserAdmin)



class WhitelistAdmin(admin.ModelAdmin):
    list_display = ('email', 'whitelist_phone')
    actions = ['modify_whitelist_file']
    
    def modify_whitelist_file(self, request, queryset):

        modification = "Modified content\n"  
        
        for whitelist in queryset:
            if whitelist.whitelist_phone:
                
                with whitelist.whitelist_phone.open('a') as file: 
                    file.write(modification)
        
       
        self.message_user(request, "Whitelist files have been modified.")

    
    modify_whitelist_file.short_description = "Modify whitelist files"

class BlacklistAdmin(admin.ModelAdmin):
    list_display = ('email', 'blacklist_phone')
    actions = ['modify_blacklist_file']
    
    def modify_blacklist_file(self, request, queryset):

        modification = "Modified content\n"
        for blacklist in queryset:
            if blacklist.blacklist_phone:

                with blacklist.blacklist_phone.open('a') as file:
                    file.write(modification)
        

        self.message_user(request, "Blacklist files have been modified.")


    modify_blacklist_file.short_description = "Modify blacklist files"


admin.site.register(Whitelist, WhitelistAdmin)
admin.site.register(Blacklist, BlacklistAdmin)

from django.contrib import admin
from .models import MessageSendInfo

class MessageSendInfoAdmin(admin.ModelAdmin):
    list_display = (
        'email',  # Displays the CustomUser instance's __str__ representation (e.g., email)
        'message_date',
        'message_delivery',
        'message_send',
        'message_failed',
    )
    list_filter = (
        'email',  # Filter by the foreign key (CustomUser)
        'message_date',
    )
    search_fields = (
        'email__email',  # Search by the related CustomUser's email field
    )
    date_hierarchy = 'message_date'
    ordering = ('-message_date',)  # Order results by message date descending

    # Define the fields to display in the admin form
    fields = (
        'email',
        'message_date',
        'message_delivery',
        'message_send',
        'message_failed',
    )

# Register MessageSendInfoAdmin with the admin site
admin.site.register(MessageSendInfo, MessageSendInfoAdmin)
