import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TextInput,
  Image,
  TouchableOpacity,
  SafeAreaView,
} from 'react-native';
import { Feather } from '@expo/vector-icons';
import { useNavigation } from '@react-navigation/native';
import Footer from './Footer';
import { socket, connect, disconnect, sendMessage, onIvishResponse, onError } from './api/socket';

export default function ChatList() {
  const navigation = useNavigation();
  const [selectedId, setSelectedId] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [chatData, setChatData] = useState([]);
  const flatListRef = useRef(null);

  useEffect(() => {
    // Connect socket with token (replace with actual token)
    const token = "your-auth-token";
    connect(token);

    // Listen for Ivish AI responses
    const handleIvishResponse = (response) => {
      // Update chat data with new response
      setChatData((prevData) => {
        // For chat list, we might want to update the last message of a conversation
        // This is a simplified implementation - in a real app, you'd have conversation IDs
        const newMessage = {
          id: Date.now().toString(),
          name: 'Ivish AI',
          message: response.text || response.message || 'New response',
          time: new Date().toLocaleTimeString(),
          avatar: 'https://randomuser.me/api/portraits/bot/1.jpg'
        };
        return [newMessage, ...prevData.slice(0, 9)]; // Keep only 10 recent items
      });
    };

    // Listen for errors
    const handleError = (error) => {
      console.error('Socket error:', error);
      // Could show error toast or notification here
    };

    onIvishResponse(handleIvishResponse);
    onError(handleError);

    return () => {
      disconnect();
      socket.off("response", handleIvishResponse);
      socket.off("error", handleError);
    };
  }, []);

  const filteredChatData = chatData.filter(item =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleChatItemPress = (item) => {
    setSelectedId(item.id);
    navigation.navigate('ChatHeaderScreen', { 
      chatItem: item,
      user: { // Replace with actual user data if available
        id: 'user1',
        name: 'You',
        avatar: 'https://randomuser.me/api/portraits/men/1.jpg',
        lastSeen: 'online'
      }
    });
  };

  const renderItem = ({ item }) => (
    <TouchableOpacity 
      onPress={() => handleChatItemPress(item)}
      activeOpacity={0.7}
    >
      <View style={[
        styles.chatItem, 
        selectedId === item.id && styles.highlighted
      ]}>
        <Image source={{ uri: item.avatar || 'https://randomuser.me/api/portraits/men/1.jpg' }} style={styles.avatar} />
        <View style={styles.messageContent}>
          <Text style={styles.name}>{item.name || 'Unknown'}</Text>
          <Text style={styles.message}>{item.message || ''}</Text>
        </View>
        <Text style={styles.time}>{item.time || ''}</Text>
      </View>
    </TouchableOpacity>
  );

  return (
    <View style={{flex: 1}}>
      <SafeAreaView style={styles.container}>
        <View style={styles.headerContainer}>
          <Text style={styles.header}>Chat</Text>
        </View>

        <View style={styles.searchBox}>
          <Feather name="search" size={18} color="#555" />
          <TextInput
            placeholder="Search by name"
            placeholderTextColor="#999"
            style={styles.input}
            value={searchQuery}
            onChangeText={setSearchQuery}
            autoCorrect={false}
          />
          {searchQuery.length > 0 && (
            <TouchableOpacity onPress={() => setSearchQuery('')}>
              <Feather name="x" size={18} color="#555" />
            </TouchableOpacity>
          )}
        </View>

        <View style={styles.listContainer}>
          {filteredChatData.length > 0 ? (
            <FlatList
              ref={flatListRef}
              data={filteredChatData}
              renderItem={renderItem}
              keyExtractor={(item) => item.id}
              showsVerticalScrollIndicator={true}
              scrollIndicatorInsets={{ right: 1 }}
              indicatorStyle="black"
              contentContainerStyle={styles.listContent}
            />
          ) : (
            <View style={styles.noResults}>
              <Text style={styles.noResultsText}>No matches found for "{searchQuery}"</Text>
            </View>
          )}
        </View>
      </SafeAreaView>
      <Footer/>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f0f',
  },
  headerContainer: {
    paddingHorizontal: 20,
    paddingTop: 16,
  },
  header: {
    top:20,
    fontSize: 24,
    fontWeight: '600',
    color: '#fff',
    marginBottom: 16,
  },
  searchBox: {
     top:10,
    backgroundColor: '#1a1a1a',
    flexDirection: 'row',
    alignItems: 'center',
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 8,
    marginHorizontal: 20,
    marginBottom: 16,
  },
  input: {
    marginLeft: 8,
    color: '#fff',
    fontSize: 16,
    flex: 1,
  },
  listContainer: {
    flex: 1,
    paddingHorizontal: 20,
  },
  listContent: {
    paddingBottom: 20,
  },
  chatItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1a1a1a',
    borderRadius: 16,
    padding: 12,
    marginBottom: 6,
  },
  highlighted: {
    backgroundColor: '#f89d28',
  },
  avatar: {
    width: 42,
    height: 42,
    borderRadius: 21,
    marginRight: 12,
  },
  messageContent: {
    flex: 1,
  },
  name: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  message: {
    color: '#ccc',
    fontSize: 13,
    marginTop: 2,
  },
  time: {
    color: '#ccc',
    fontSize: 12,
  },
  noResults: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  noResultsText: {
    color: '#ccc',
    fontSize: 16,
  },
});
