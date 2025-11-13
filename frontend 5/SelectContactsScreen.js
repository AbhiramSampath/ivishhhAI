import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  Alert,
  SafeAreaView,
  Modal,
  StatusBar,
  PermissionsAndroid,
  Platform,
} from 'react-native';
import { Feather } from '@expo/vector-icons';
import * as Contacts from 'expo-contacts';
import * as SMS from 'expo-sms';
import * as Linking from 'expo-linking';
import { useNavigation } from '@react-navigation/native';
import { checkUserExists } from './api';

export default function SelectContactsScreen() {
  const navigation = useNavigation();
  const [contacts, setContacts] = useState([]);
  const [filteredContacts, setFilteredContacts] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [inviteModalVisible, setInviteModalVisible] = useState(false);
  const [selectedContact, setSelectedContact] = useState(null);

  useEffect(() => {
    requestContactsPermission();
  }, []);

  useEffect(() => {
    const filtered = contacts.filter(contact =>
      contact.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      contact.phoneNumbers?.some(phone =>
        phone.number.includes(searchQuery)
      )
    );
    setFilteredContacts(filtered);
  }, [contacts, searchQuery]);

  const requestContactsPermission = async () => {
    try {
      const { status } = await Contacts.requestPermissionsAsync();
      if (status === 'granted') {
        loadContacts();
      } else {
        Alert.alert(
          'Permission Required',
          'Contacts permission is required to select contacts.',
          [{ text: 'OK', onPress: () => navigation.goBack() }]
        );
      }
    } catch (error) {
      console.error('Error requesting contacts permission:', error);
      Alert.alert('Error', 'Failed to request contacts permission.');
    }
  };

  const loadContacts = async () => {
    try {
      const { data } = await Contacts.getContactsAsync({
        fields: [Contacts.Fields.PhoneNumbers, Contacts.Fields.Name],
      });

      // Filter contacts with phone numbers and add exists check
      const contactsWithPhones = await Promise.all(
        data
          .filter(contact => contact.phoneNumbers && contact.phoneNumbers.length > 0)
          .map(async (contact) => {
            const phoneNumber = contact.phoneNumbers[0].number.replace(/\D/g, '');
            let existsOnVerbX = false;
            try {
              existsOnVerbX = await checkUserExists(phoneNumber);
            } catch (error) {
              console.error('Error checking user exists:', error);
            }

            return {
              id: contact.id,
              name: contact.name,
              phoneNumbers: contact.phoneNumbers,
              existsOnVerbX,
            };
          })
      );

      setContacts(contactsWithPhones);
      setLoading(false);
    } catch (error) {
      console.error('Error loading contacts:', error);
      Alert.alert('Error', 'Failed to load contacts.');
      setLoading(false);
    }
  };

  const handleContactPress = async (contact) => {
    if (contact.existsOnVerbX) {
      // Start chat with existing VerbX user
      navigation.navigate('ChatHeaderScreen', {
        chatItem: {
          id: contact.id,
          name: contact.name,
          message: 'Start a conversation',
          time: new Date().toLocaleTimeString(),
          avatar: 'https://randomuser.me/api/portraits/men/1.jpg',
          phoneNumber: contact.phoneNumbers[0].number,
        },
        user: {
          id: 'currentUser',
          name: 'You',
          avatar: 'https://randomuser.me/api/portraits/men/2.jpg',
          lastSeen: 'online'
        }
      });
    } else {
      // Show invite options for non-VerbX users
      showInviteOptions(contact);
    }
  };

  const showInviteOptions = (contact) => {
    setSelectedContact(contact);
    setInviteModalVisible(true);
  };

  const inviteViaWhatsApp = async (contact) => {
    setInviteModalVisible(false);
    const phoneNumber = contact.phoneNumbers[0].number.replace(/\D/g, '');
    const message = `Hey ${contact.name}! Join me on VerbX for seamless language translation and communication. Download now: [App Link]`;
    const whatsappUrl = `whatsapp://send?phone=${phoneNumber}&text=${encodeURIComponent(message)}`;

    try {
      const supported = await Linking.canOpenURL(whatsappUrl);
      if (supported) {
        await Linking.openURL(whatsappUrl);
      } else {
        Alert.alert('WhatsApp not installed', 'Please install WhatsApp to send invites.');
      }
    } catch (error) {
      console.error('Error opening WhatsApp:', error);
      Alert.alert('Error', 'Failed to open WhatsApp.');
    }
  };

  const inviteViaSMS = async (contact) => {
    setInviteModalVisible(false);
    const phoneNumber = contact.phoneNumbers[0].number;
    const message = `Hey ${contact.name}! Join me on VerbX for seamless language translation and communication. Download now: [App Link]`;

    try {
      const isAvailable = await SMS.isAvailableAsync();
      if (isAvailable) {
        await SMS.sendSMSAsync([phoneNumber], message);
      } else {
        Alert.alert('SMS not available', 'SMS is not available on this device.');
      }
    } catch (error) {
      console.error('Error sending SMS:', error);
      Alert.alert('Error', 'Failed to send SMS.');
    }
  };

  const renderContact = ({ item }) => (
    <TouchableOpacity
      style={styles.contactItem}
      onPress={() => handleContactPress(item)}
    >
      <View style={styles.contactInfo}>
        <Text style={styles.contactName}>{item.name}</Text>
        <Text style={styles.contactPhone}>
          {item.phoneNumbers[0].number}
        </Text>
      </View>
      <View style={styles.contactActions}>
        {item.existsOnVerbX ? (
          <View style={styles.verbxBadge}>
            <Text style={styles.verbxBadgeText}>On VerbX</Text>
          </View>
        ) : (
          <Feather name="user-plus" size={20} color="#FFA364" />
        )}
      </View>
    </TouchableOpacity>
  );

  if (loading) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.loadingContainer}>
          <Text style={styles.loadingText}>Loading contacts...</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#0f0f0f" />
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Feather name="arrow-left" size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Select Contact</Text>
        <View style={{ width: 24 }} />
      </View>

      <View style={styles.searchContainer}>
        <Feather name="search" size={18} color="#555" />
        <TextInput
          style={styles.searchInput}
          placeholder="Search contacts..."
          placeholderTextColor="#999"
          value={searchQuery}
          onChangeText={setSearchQuery}
        />
      </View>

      <FlatList
        data={filteredContacts}
        renderItem={renderContact}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.contactsList}
      />

      <Modal
        visible={inviteModalVisible}
        transparent={true}
        animationType="fade"
        onRequestClose={() => setInviteModalVisible(false)}
        statusBarTranslucent={true}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Invite {selectedContact?.name}</Text>
            <Text style={styles.modalSubtitle}>
              This contact is not on VerbX yet. How would you like to invite them?
            </Text>

            <TouchableOpacity
              style={styles.inviteOption}
              onPress={() => inviteViaWhatsApp(selectedContact)}
            >
              <Feather name="message-circle" size={24} color="#25D366" />
              <Text style={styles.inviteOptionText}>Invite via WhatsApp</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.inviteOption}
              onPress={() => inviteViaSMS(selectedContact)}
            >
              <Feather name="message-square" size={24} color="#FFA364" />
              <Text style={styles.inviteOptionText}>Invite via SMS</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.cancelButton}
              onPress={() => setInviteModalVisible(false)}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f0f',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 16,
    paddingTop: Platform.OS === 'android' ? 50 : 16,
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#fff',
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1a',
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 8,
    marginHorizontal: 20,
    marginBottom: 16,
  },
  searchInput: {
    marginLeft: 8,
    color: '#fff',
    fontSize: 16,
    flex: 1,
  },
  contactsList: {
    paddingHorizontal: 20,
    paddingBottom: 20,
  },
  contactItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1a',
    borderRadius: 16,
    padding: 16,
    marginBottom: 8,
  },
  contactInfo: {
    flex: 1,
  },
  contactName: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  contactPhone: {
    color: '#ccc',
    fontSize: 14,
    marginTop: 2,
  },
  contactActions: {
    alignItems: 'center',
  },
  verbxBadge: {
    backgroundColor: '#FFA364',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 12,
  },
  verbxBadgeText: {
    color: '#000',
    fontSize: 12,
    fontWeight: '600',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: '#fff',
    fontSize: 16,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.7)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalContent: {
    backgroundColor: '#1a1a1a',
    borderRadius: 20,
    padding: 24,
    marginHorizontal: 20,
    width: '90%',
    maxWidth: 400,
    maxHeight: '80%',
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#fff',
    textAlign: 'center',
    marginBottom: 8,
  },
  modalSubtitle: {
    fontSize: 16,
    color: '#ccc',
    textAlign: 'center',
    marginBottom: 24,
    lineHeight: 22,
  },
  inviteOption: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#2a2a2a',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
  },
  inviteOptionText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 12,
  },
  cancelButton: {
    backgroundColor: '#333',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    marginTop: 8,
  },
  cancelButtonText: {
    color: '#FFA364',
    fontSize: 16,
    fontWeight: '600',
  },
});
