import React from 'react';
import { View, Text, Pressable, StyleSheet } from 'react-native';
import Svg, { Path } from 'react-native-svg';

const AvatarCreationCard = ({ onPress }) => (
  <Pressable
    style={({ pressed }) => [
      styles.card,
      pressed && styles.cardPressed,
    ]}
    onPress={onPress}
    accessibilityRole="button"
    accessibilityLabel="Create your own avatar"
  >
    <Text style={styles.text}>Create your Own Avatar</Text>
    <View style={styles.iconCircle}>
      <Svg width={24} height={24} viewBox="0 0 25 25" fill="none">
        <Path
          d="M24.6607 2.54666C24.6607 1.57793 23.8754 0.792622 22.9067 0.792622L7.1204 0.792622C6.15167 0.792621 5.36637 1.57793 5.36637 2.54666C5.36636 3.51538 6.15167 4.30069 7.1204 4.30069H21.1527V18.333C21.1527 19.3017 21.938 20.087 22.9067 20.087C23.8754 20.087 24.6607 19.3017 24.6607 18.333L24.6607 2.54666ZM2 23.4534L3.24029 24.6937L24.147 3.78695L22.9067 2.54666L21.6664 1.30637L0.75971 22.2131L2 23.4534Z"
          fill="white"
        />
      </Svg>
    </View>
  </Pressable>
);

const styles = StyleSheet.create({
  card: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#FFA364',
    paddingHorizontal: 0,
    paddingVertical: 12,
    paddingLeft:10,
    paddingRight:10,
    borderRadius: 20,
    marginBottom: 6,
    width: '100%',
  },
  cardPressed: { 
    backgroundColor: '#FF9A5A',
  },
  text: {
    color: 'black',
    fontSize: 22,
    fontWeight: '500',
    flexShrink: 1,
  },
  iconCircle: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: '#0E0F13',
    justifyContent: 'center',
    alignItems: 'center',
  },
});

export default AvatarCreationCard;
