import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { getUserDetails } from './api';

// Standard Back Button Component
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

export default function AccountDetails() {
  const navigation = useNavigation();
  const [userDetails, setUserDetails] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUserDetails = async () => {
      try {
        const userId = 'dummy_user_token_1234567890'; // Use appropriate user ID
        const data = await getUserDetails(userId);
        setUserDetails(data);
      } catch (error) {
        console.error('Failed to fetch user details:', error);
        // Handle error, perhaps show a message
      } finally {
        setLoading(false);
      }
    };
    fetchUserDetails();
  }, []);

  if (loading) {
    return (
      <View style={styles.container}>
        <View style={styles.header}>
          <TouchableOpacity onPress={() => navigation.goBack()}>
            <NavIconsBack />
          </TouchableOpacity>
          <Text style={styles.headerTitle}>Account Details</Text>
        </View>
        <View style={styles.loadingContainer}>
          <Text>Loading...</Text>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Account Details</Text>
      </View>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        {userDetails && (
          <View style={styles.detailsContainer}>
            <Text style={styles.label}>Name</Text>
            <Text style={styles.value}>{userDetails.name || 'N/A'}</Text>
            <Text style={styles.label}>Email</Text>
            <Text style={styles.value}>{userDetails.email || 'N/A'}</Text>
            {/* Add more fields as needed based on API response */}
          </View>
        )}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
    paddingTop: 44,
    paddingHorizontal: 20,
    paddingBottom: 4,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
  },
  scrollContent: {
    paddingHorizontal: 20,
    paddingTop: 20,
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  detailsContainer: {
    // Add styles as needed
  },
  label: {
    fontSize: 16,
    fontWeight: '500',
    color: '#2C2C2C',
    marginBottom: 5,
  },
  value: {
    fontSize: 16,
    color: '#0C0D11',
    marginBottom: 15,
  },
  navIconsBackContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 36,
    width: 36,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
  },
  vector: {
    position: 'absolute',
    flexShrink: 0,
    top: 12,
    right: 21,
    bottom: 12,
    left: 9,
    overflow: 'visible',
  },
});
