import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View,
  Text,
  Image,
  StyleSheet,
  TouchableOpacity,
  TextInput,
  ScrollView,
  KeyboardAvoidingView,
  Platform,
  Animated,
  Modal,
  Alert,
  Dimensions,
  Pressable
} from 'react-native';
import Icon from 'react-native-vector-icons/MaterialIcons';
import Ionicons from 'react-native-vector-icons/Ionicons';
import { useNavigation } from '@react-navigation/native';
import { socket, connect, disconnect, onMessage, onIvishResponse, sendMessage, onError } from './api/socket';

const { width } = Dimensions.get('window');

export default function ChatHeaderScreen({ route }) {
  
  const { chatItem = {}, user = {}, initialMessages = [] } = route?.params || {};
  
  // Set default values
  const defaultChatItem = {
    avatar: 'https://randomuser.me/api/portraits/men/1.jpg',
    name: 'Unknown User',
    lastSeen: 'recently',
    ...chatItem
  };

  const defaultUser = {
    id: 'user1',
    name: 'You',
    avatar: 'https://randomuser.me/api/portraits/women/1.jpg',
    lastSeen: 'online',
    ...user
  };

  const [messages, setMessages] = useState(initialMessages);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [contextMenuVisible, setContextMenuVisible] = useState(false);
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [showBackground, setShowBackground] = useState(messages.length === 0);
  const scrollViewRef = useRef();
  const dotAnimations = [useRef(new Animated.Value(0)).current, useRef(new Animated.Value(0)).current, useRef(new Animated.Value(0)).current];

  // Real socket connection status
  const [isConnected, setIsConnected] = useState(false);

  const navigation = useNavigation();

  useEffect(() => {
    setShowBackground(messages.length === 0);
  }, [messages]);

  // Socket event listeners and connection
  useEffect(() => {
    // Connect to socket (using a mock token for now - should be replaced with real auth)
    const token = 'mock-jwt-token'; // TODO: Replace with actual JWT token from auth
    connect(token);

    // Listen for incoming messages from backend
    const unsubscribeMessage = onMessage((data) => {
      const newMessage = {
        id: Date.now().toString(),
        text: data.text || data.message,
        isUser: false,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, newMessage]);
    });

    // Listen for Ivish responses
    const unsubscribeIvish = onIvishResponse((data) => {
      const newMessage = {
        id: Date.now().toString(),
        text: data.text || data.message,
        isUser: false,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, newMessage]);
    });

    // Listen for socket errors
    const unsubscribeError = onError((error) => {
      console.error('Socket error:', error);
      setIsConnected(false);
    });

    // Check socket connection status
    const checkConnection = () => {
      setIsConnected(socket.connected);
    };

    checkConnection();
    const interval = setInterval(checkConnection, 1000);

    return () => {
      unsubscribeMessage();
      unsubscribeIvish();
      unsubscribeError();
      clearInterval(interval);
      disconnect();
    };
  }, []);

  // Wrap animateDots in useCallback to prevent unnecessary recreations
  const animateDots = useCallback(() => {
    const animation = (dot) => {
      return Animated.loop(
        Animated.sequence([
          Animated.timing(dot, {
            toValue: -5,
            duration: 300,
            useNativeDriver: true,
          }),
          Animated.timing(dot, {
            toValue: 0,
            duration: 300,
            useNativeDriver: true,
          }),
        ]),
        { iterations: -1 }
      );
    };

    dotAnimations.forEach(dot => animation(dot).start());
    return () => {
      dotAnimations.forEach(dot => animation(dot).stop());
    };
  }, [dotAnimations]);

  useEffect(() => {
    if (isTyping) {
      animateDots();
    } else {
      dotAnimations.forEach(dot => {
        const animation = dot.stopAnimation();
        return () => animation?.stop();
      });
    }
  }, [isTyping, animateDots, dotAnimations]);

  const handleSend = () => {
    if (inputText.trim()) {
      const newMessage = {
        id: Date.now().toString(),
        text: inputText,
        isUser: true,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages(prev => [...prev, newMessage]);
      setInputText('');
      setIsTyping(false);

      // Send message via socket to backend
      sendMessage(inputText);
    }
  };

  const handleTyping = (text) => {
    setInputText(text);
    setIsTyping(text.length > 0);
  };

  const showContextMenu = (message) => {
    setSelectedMessage(message);
    setContextMenuVisible(true);
  };

  const hideContextMenu = () => {
    setContextMenuVisible(false);
    setSelectedMessage(null);
  };

  const handleDelete = () => {
    if (selectedMessage) {
      setMessages(messages.filter(msg => msg.id !== selectedMessage.id));
      hideContextMenu();
    }
  };

  const handleReply = () => {
    if (selectedMessage) {
      setInputText(`Replying to "${selectedMessage.text}" `);
      hideContextMenu();
    }
  };

  const handleCopy = () => {
    if (selectedMessage) {
      Alert.alert('Copied', 'Message copied to clipboard');
      hideContextMenu();
    }
  };

  const handleMicPress = () => {
    Alert.alert('Microphone', 'Voice recording started');
  };

  const handleCameraPress = () => {
    Alert.alert('Camera', 'Open camera for photos');
  };

  return (
    <View style={styles.container}>
      {/* Background Image (only shown when no messages) */}
      {showBackground && (
        <View style={styles.backgroundContainer}>
          <Image 
            source={require('./assets/img.png')} 
            style={styles.backgroundImage}
            resizeMode="contain"
          />
          <View style={styles.center}>
            <Text style={styles.centerText}>Start a Conversation</Text>
          </View>
        </View>
      )}

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.userInfo}>
          <TouchableOpacity style={styles.backButton} onPress={() => navigation.navigate('ChatList')}>
            <Ionicons name="arrow-back" size={28} color="#fff" />
          </TouchableOpacity>
          <View style={styles.avatarContainer}>
            <Image 
              source={{ uri: defaultChatItem.avatar }} 
              style={styles.avatar} 
            />
            <View style={[
              styles.connectionStatus,
              { backgroundColor: isConnected ? '#4CAF50' : '#F44336' }
            ]} />
          </View>
          <View style={styles.userTextContainer}>
            <Text style={styles.name}>{defaultChatItem.name}</Text>
            <Text style={styles.status}>
              {isTyping ? 'typing...' : `last seen ${defaultChatItem.lastSeen}`}
            </Text>
          </View>
        </View>

        <View style={styles.iconSet}>
          <TouchableOpacity style={styles.iconButton} onPress={() => navigation.navigate('Voicecall')}>
            <Image 
              source={require('./assets/call.png')}
              style={styles.headerIcon}
            />
          </TouchableOpacity>
          <TouchableOpacity style={styles.iconButton}>
            <Image 
              source={require('./assets/video.png')}
              style={styles.headerIcon}
            />
          </TouchableOpacity>
        </View>
      </View>

      {/* Chat Messages */}
      <ScrollView 
        ref={scrollViewRef}
        contentContainerStyle={styles.messagesContainer}
        onContentSizeChange={() => scrollViewRef.current?.scrollToEnd({ animated: true })}
        showsVerticalScrollIndicator={true}
      >
        {messages.map((message) => (
          <Pressable
            key={message.id}
            onLongPress={() => showContextMenu(message)}
            delayLongPress={200}
            activeOpacity={0.7}
          >
            <View
              style={[
                styles.messageBubble,
                message.isUser ? styles.userBubble : styles.recipientBubble,
              ]}
            >
              <Text style={message.isUser ? styles.userText : styles.recipientText}>
                {message.text}
              </Text>
              <View style={styles.timeContainer}>
                <Text style={message.isUser ? styles.userTime : styles.recipientTime}>
                  {message.time}
                </Text>
                {message.isUser && (
                  <Icon 
                    name="done-all" 
                    size={14} 
                    color="#4fc3f7" 
                    style={styles.statusIcon}
                  />
                )}
              </View>
            </View>
          </Pressable>
        ))}
      </ScrollView>

      {/* Context Menu */}
      <Modal
        transparent={true}
        visible={contextMenuVisible}
        onRequestClose={hideContextMenu}
      >
        <TouchableOpacity
          style={styles.contextMenuOverlay}
          activeOpacity={1}
          onPress={hideContextMenu}
        >
          <View style={styles.contextMenu}>
            <TouchableOpacity style={styles.menuItem} onPress={handleReply}>
              <Icon name="reply" size={20} color="#fff" style={styles.menuIcon} />
              <Text style={styles.menuText}>Reply</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={handleCopy}>
              <Icon name="content-copy" size={20} color="#fff" style={styles.menuIcon} />
              <Text style={styles.menuText}>Copy</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.menuItem} onPress={handleDelete}>
              <Icon name="delete" size={20} color="#ff4444" style={styles.menuIcon} />
              <Text style={[styles.menuText, styles.deleteText]}>Delete</Text>
            </TouchableOpacity>
          </View>
        </TouchableOpacity>
      </Modal>

      {/* Typing Indicator */}
      {isTyping && (
        <View style={styles.typingContainer}>
          <View style={styles.typingBubble}>
            {dotAnimations.map((animation, index) => (
              <Animated.View
                key={index}
                style={[
                  styles.typingDot,
                  { transform: [{ translateY: animation }] }
                ]}
              />
            ))}
          </View>
        </View>
      )}

      {/* Bottom Input */}
      <View style={styles.bottomBar}>
        <View style={[
          styles.inputContainer,
          isTyping && styles.inputContainerTyping
        ]}>
          <TextInput
            style={styles.input}
            placeholder="Message"
            placeholderTextColor="#aaa"
            value={inputText}
            onChangeText={handleTyping}
            onSubmitEditing={handleSend}
            multiline
          />
        </View>
        
        {/* Show microphone and camera when not typing, show send button when typing */}
        {!isTyping ? (
          <View style={styles.attachmentButtons}>
            <TouchableOpacity onPress={handleCameraPress} style={styles.attachmentButton}>
              <Icon name="camera-alt" size={20} color= '#ffffff' />
            </TouchableOpacity>
            <TouchableOpacity onPress={handleMicPress} style={styles.attachmentButton}>
              <Icon name="mic" size={20} color= '#ffffff' />
            </TouchableOpacity>
          </View>
        ) : (
          <TouchableOpacity 
            style={styles.sendButton} 
            onPress={handleSend} 
            disabled={!inputText.trim()}
          >
            <Image 
              source={require('./assets/message21.png')}
              style={styles.rightIconImage}
            />
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f0f0f',
    paddingTop: 40,
    paddingHorizontal: 16,
  },
  backgroundContainer: {
    position: 'absolute',
    width: '100%',
    height: '100%',
    justifyContent: 'center',
    alignItems: 'center',
    bottom: 9,
  },
  backgroundImage: {
    width: 100,
    height: 100,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
    zIndex: 1,
  },
  userInfo: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  avatarContainer: {
    marginRight: 12,
    position: 'relative',
  },
  avatar: {
    width: 50,
    height: 50,
    borderRadius: 25,
    borderWidth: 2,
    borderColor: '#ff8c00',
  },
  connectionStatus: {
    position: 'absolute',
    bottom: 0,
    right: 0,
    width: 12,
    height: 12,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: '#0f0f0f',
  },
  userTextContainer: {
    justifyContent: 'center',
  },
  name: {
    color: '#fff',
    fontSize: 18,
    fontWeight: 'bold',
  },
  status: {
    color: '#aaa',
    fontSize: 12,
    marginTop: 2,
  },
  iconSet: {
    flexDirection: 'row',
    gap: 12,
  },
  iconButton: {
    padding: 3,
  },
  headerIcon: {
    width: 28,
    height: 28,
  },
  center: {
    position: 'absolute',
    justifyContent: 'center',
    alignItems: 'center',
  },
  centerText: {
    color: '#fff',
    fontSize: 16,
    opacity: 0.8,
    marginTop: 120,
  },
  messagesContainer: {
    flexGrow: 1,
    paddingVertical: 16,
  },
  messageBubble: {
    maxWidth: '80%',
    padding: 12,
    borderRadius: 16,
    marginBottom: 8,
  },
  userBubble: {
    alignSelf: 'flex-end',
    backgroundColor: '#ff8c00',
    borderBottomRightRadius: 4,
  },
  recipientBubble: {
    alignSelf: 'flex-start',
    backgroundColor: '#1a1a1a',
    borderBottomLeftRadius: 4,
  },
  userText: {
    color: '#fff',
    fontSize: 16,
  },
  recipientText: {
    color: '#fff',
    fontSize: 16,
  },
  timeContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'flex-end',
    marginTop: 4,
  },
  userTime: {
    color: '#fff',
    fontSize: 10,
    marginRight: 4,
    opacity: 0.8,
  },
  recipientTime: {
    color: '#aaa',
    fontSize: 10,
    marginRight: 4,
  },
  statusIcon: {
    marginLeft: 4,
  },
  typingContainer: {
    marginBottom: 4,
    marginLeft: 12,
  },
  typingBubble: {
    backgroundColor: '#1a1a1a',
    borderRadius: 16,
    paddingHorizontal: 12,
    paddingVertical: 8,
    alignSelf: 'flex-start',
    flexDirection: 'row',
    alignItems: 'center',
  },
  typingDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: '#fff',
    marginHorizontal: 2,
  },
  bottomBar: {
    backgroundColor: '#1a1a1a',
    borderRadius: 40,
    marginBottom: 16,
    flexDirection: 'row',
    alignItems: 'center',
    padding: 8,
  },
  inputContainer: {
    flex: 1,
    backgroundColor: '#1a1a1a',
    borderRadius: 20,
    paddingHorizontal: 12,
    height: 40,
    marginRight: 8,
  },
  inputContainerTyping: {
    backgroundColor: '#2a2a2a',
  },
  input: {
    flex: 1,
    color: '#fff',
    fontSize: 16,
    paddingVertical: 8,
    height: 40,
  },
  attachmentButtons: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  attachmentButton: {
    padding: 3,
    marginLeft: 1,
  },
  sendButton: {
    padding: 8,
    marginLeft: 8,
  },
  rightIconImage: {
    width: 24,
    height: 24,
  },
  contextMenuOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.2)',
  },
  contextMenu: {
    position: 'absolute',
    backgroundColor: '#1a1a1a',
    borderRadius: 12,
    paddingVertical: 8,
    width: 200,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 4,
    elevation: 5,
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 10,
    paddingHorizontal: 16,
  },
  menuIcon: {
    marginRight: 12,
  },
  menuText: {
    color: '#fff',
    fontSize: 16,
  },
  deleteText: {
    color: '#ff4444',
  },
  backButton: {
    marginRight: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
