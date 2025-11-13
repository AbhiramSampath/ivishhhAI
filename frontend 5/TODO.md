# TODO: Implement Add Contacts Functionality

## Completed Tasks
- [x] Install expo-contacts and expo-sms packages
- [x] Add checkUserExists API function to api/index.js
- [x] Create SelectContactsScreen.js with contact selection, VerbX user checking, and invite functionality
- [x] Add SelectContactsScreen to App.js navigation
- [x] Update chatsScreen.js to show "Add Contacts" button when no chats exist

## Remaining Tasks
- [ ] Test contact permissions and access
- [ ] Test WhatsApp and SMS invite functionality
- [ ] Test navigation between screens
- [ ] Verify API integration for user existence checks
- [ ] Test empty state UI in chat list

## Testing Checklist
- [ ] Grant contacts permission when prompted
- [ ] Verify contacts load correctly
- [ ] Check VerbX user badges appear for existing users
- [ ] Test invite options for non-VerbX users
- [ ] Verify WhatsApp invite opens WhatsApp with correct message
- [ ] Verify SMS invite opens SMS app with correct message
- [ ] Test navigation back from SelectContactsScreen
- [ ] Test starting chat with VerbX users
- [ ] Verify empty state shows when no chats and no search query
- [ ] Verify search functionality works in both screens
