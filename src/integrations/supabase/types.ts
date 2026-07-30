export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.4"
  }
  public: {
    Tables: {
      alerts_history: {
        Row: {
          alerted_at: string
          asn: string
          id: string
          risk_label: string
          risk_score: number
          sources: Json
          ti_summary: string | null
        }
        Insert: {
          alerted_at?: string
          asn: string
          id?: string
          risk_label: string
          risk_score: number
          sources?: Json
          ti_summary?: string | null
        }
        Update: {
          alerted_at?: string
          asn?: string
          id?: string
          risk_label?: string
          risk_score?: number
          sources?: Json
          ti_summary?: string | null
        }
        Relationships: []
      }
      as_attack_samples: {
        Row: {
          asn: string
          bgp_events_count_30m: number
          created_at: string
          external_anomalies_count_30m: number
          external_strong_anomalies_count_30m: number
          gn_malicious_ratio: number | null
          gn_noise_ratio: number | null
          gn_riot_ratio: number | null
          id: string
          qrator_events_count_30m: number
          ripe_events_count_30m: number
          ripestat_events_count_30m: number
          rpki_events_count_30m: number
          ti_abuse_avg_score: number
          ti_abuse_high_ratio: number
          ti_combined_score: number | null
          ti_ips_total: number
          timestamp: string
          wanguard_attack_count_30m: number
          wanguard_is_under_attack: boolean
          wanguard_max_bps_30m: number | null
          wanguard_max_pps_30m: number | null
          wanguard_severity_class: string
        }
        Insert: {
          asn?: string
          bgp_events_count_30m?: number
          created_at?: string
          external_anomalies_count_30m?: number
          external_strong_anomalies_count_30m?: number
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          id?: string
          qrator_events_count_30m?: number
          ripe_events_count_30m?: number
          ripestat_events_count_30m?: number
          rpki_events_count_30m?: number
          ti_abuse_avg_score?: number
          ti_abuse_high_ratio?: number
          ti_combined_score?: number | null
          ti_ips_total?: number
          timestamp: string
          wanguard_attack_count_30m?: number
          wanguard_is_under_attack?: boolean
          wanguard_max_bps_30m?: number | null
          wanguard_max_pps_30m?: number | null
          wanguard_severity_class?: string
        }
        Update: {
          asn?: string
          bgp_events_count_30m?: number
          created_at?: string
          external_anomalies_count_30m?: number
          external_strong_anomalies_count_30m?: number
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          id?: string
          qrator_events_count_30m?: number
          ripe_events_count_30m?: number
          ripestat_events_count_30m?: number
          rpki_events_count_30m?: number
          ti_abuse_avg_score?: number
          ti_abuse_high_ratio?: number
          ti_combined_score?: number | null
          ti_ips_total?: number
          timestamp?: string
          wanguard_attack_count_30m?: number
          wanguard_is_under_attack?: boolean
          wanguard_max_bps_30m?: number | null
          wanguard_max_pps_30m?: number | null
          wanguard_severity_class?: string
        }
        Relationships: []
      }
      asn_alert_state: {
        Row: {
          asn: string
          last_alert_at: string
          last_risk_label: string
          last_risk_score: number
        }
        Insert: {
          asn: string
          last_alert_at?: string
          last_risk_label?: string
          last_risk_score?: number
        }
        Update: {
          asn?: string
          last_alert_at?: string
          last_risk_label?: string
          last_risk_score?: number
        }
        Relationships: []
      }
      asn_incidents: {
        Row: {
          announcements: number | null
          asn: string
          bgp_state: string | null
          created_at: string
          id: string
          name: string
          packet_loss_percent: number | null
          signals: string[]
          status: string
          visibility_percent: number | null
          withdrawals: number | null
        }
        Insert: {
          announcements?: number | null
          asn: string
          bgp_state?: string | null
          created_at?: string
          id?: string
          name: string
          packet_loss_percent?: number | null
          signals?: string[]
          status: string
          visibility_percent?: number | null
          withdrawals?: number | null
        }
        Update: {
          announcements?: number | null
          asn?: string
          bgp_state?: string | null
          created_at?: string
          id?: string
          name?: string
          packet_loss_percent?: number | null
          signals?: string[]
          status?: string
          visibility_percent?: number | null
          withdrawals?: number | null
        }
        Relationships: []
      }
      asn_ip_reputation_window: {
        Row: {
          asn: string
          avg_score: number | null
          gn_malicious_ratio: number | null
          gn_noise_ratio: number | null
          gn_riot_ratio: number | null
          high_score_ips: number
          ips_total: number
          ips_with_score: number
          source: string
          window_end: string
          window_start: string
        }
        Insert: {
          asn: string
          avg_score?: number | null
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          high_score_ips?: number
          ips_total?: number
          ips_with_score?: number
          source?: string
          window_end: string
          window_start: string
        }
        Update: {
          asn?: string
          avg_score?: number | null
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          high_score_ips?: number
          ips_total?: number
          ips_with_score?: number
          source?: string
          window_end?: string
          window_start?: string
        }
        Relationships: []
      }
      ip_reputation: {
        Row: {
          gn_classification: string | null
          gn_last_checked: string | null
          gn_noise: boolean | null
          gn_riot: boolean | null
          ip: string
          last_checked_at: string | null
          last_seen_at: string | null
          reports_count: number | null
          reputation_score: number | null
          source: string
        }
        Insert: {
          gn_classification?: string | null
          gn_last_checked?: string | null
          gn_noise?: boolean | null
          gn_riot?: boolean | null
          ip: string
          last_checked_at?: string | null
          last_seen_at?: string | null
          reports_count?: number | null
          reputation_score?: number | null
          source?: string
        }
        Update: {
          gn_classification?: string | null
          gn_last_checked?: string | null
          gn_noise?: boolean | null
          gn_riot?: boolean | null
          ip?: string
          last_checked_at?: string | null
          last_seen_at?: string | null
          reports_count?: number | null
          reputation_score?: number | null
          source?: string
        }
        Relationships: []
      }
      monitored_asns: {
        Row: {
          asn: string
          created_at: string
          id: string
          name: string | null
          user_id: string | null
        }
        Insert: {
          asn: string
          created_at?: string
          id?: string
          name?: string | null
          user_id?: string | null
        }
        Update: {
          asn?: string
          created_at?: string
          id?: string
          name?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          display_name: string | null
          id: string
          must_change_password: boolean
          username: string
        }
        Insert: {
          created_at?: string
          display_name?: string | null
          id: string
          must_change_password?: boolean
          username: string
        }
        Update: {
          created_at?: string
          display_name?: string | null
          id?: string
          must_change_password?: boolean
          username?: string
        }
        Relationships: []
      }
      telegram_config: {
        Row: {
          chat_id: string
          created_at: string
          enabled: boolean
          id: string
          notify_attacks: boolean
          notify_recovery: boolean
          notify_warnings: boolean
          user_id: string
        }
        Insert: {
          chat_id: string
          created_at?: string
          enabled?: boolean
          id?: string
          notify_attacks?: boolean
          notify_recovery?: boolean
          notify_warnings?: boolean
          user_id: string
        }
        Update: {
          chat_id?: string
          created_at?: string
          enabled?: boolean
          id?: string
          notify_attacks?: boolean
          notify_recovery?: boolean
          notify_warnings?: boolean
          user_id?: string
        }
        Relationships: []
      }
      user_permissions: {
        Row: {
          created_at: string
          granted_by: string | null
          id: string
          permission: string
          user_id: string
        }
        Insert: {
          created_at?: string
          granted_by?: string | null
          id?: string
          permission: string
          user_id: string
        }
        Update: {
          created_at?: string
          granted_by?: string | null
          id?: string
          permission?: string
          user_id?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      v_asn_ti_reputation_7d: {
        Row: {
          asn: string | null
          avg_score_medio: number | null
          first_window: string | null
          ips_com_score: number | null
          ips_total_amostrados: number | null
          last_window: string | null
        }
        Relationships: []
      }
      v_training_dataset: {
        Row: {
          asn: string | null
          bgp_count: number | null
          bgp_events_count_30m: number | null
          external_anomalies_count_30m: number | null
          external_strong_anomalies_count_30m: number | null
          gn_malicious_ratio: number | null
          gn_noise_ratio: number | null
          gn_riot_ratio: number | null
          has_bgp: boolean | null
          has_combo_strong: boolean | null
          has_qrator: boolean | null
          has_ripe: boolean | null
          has_ripestat: boolean | null
          has_rpki: boolean | null
          has_strong_external: boolean | null
          is_attack: boolean | null
          qrator_count: number | null
          qrator_events_count_30m: number | null
          ripe_events_count_30m: number | null
          ripestat_count: number | null
          ripestat_events_count_30m: number | null
          rpki_count: number | null
          rpki_events_count_30m: number | null
          strong_count: number | null
          ti_abuse_avg_score: number | null
          ti_abuse_high_ratio: number | null
          ti_combined_score: number | null
          ti_ips_total: number | null
          timestamp: string | null
          wanguard_attack_count_30m: number | null
          wanguard_max_bps_30m: number | null
          wanguard_severity_class: string | null
        }
        Insert: {
          asn?: string | null
          bgp_count?: number | null
          bgp_events_count_30m?: number | null
          external_anomalies_count_30m?: number | null
          external_strong_anomalies_count_30m?: number | null
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          has_bgp?: never
          has_combo_strong?: never
          has_qrator?: never
          has_ripe?: never
          has_ripestat?: never
          has_rpki?: never
          has_strong_external?: never
          is_attack?: never
          qrator_count?: number | null
          qrator_events_count_30m?: number | null
          ripe_events_count_30m?: number | null
          ripestat_count?: number | null
          ripestat_events_count_30m?: number | null
          rpki_count?: number | null
          rpki_events_count_30m?: number | null
          strong_count?: number | null
          ti_abuse_avg_score?: number | null
          ti_abuse_high_ratio?: number | null
          ti_combined_score?: number | null
          ti_ips_total?: number | null
          timestamp?: string | null
          wanguard_attack_count_30m?: number | null
          wanguard_max_bps_30m?: number | null
          wanguard_severity_class?: string | null
        }
        Update: {
          asn?: string | null
          bgp_count?: number | null
          bgp_events_count_30m?: number | null
          external_anomalies_count_30m?: number | null
          external_strong_anomalies_count_30m?: number | null
          gn_malicious_ratio?: number | null
          gn_noise_ratio?: number | null
          gn_riot_ratio?: number | null
          has_bgp?: never
          has_combo_strong?: never
          has_qrator?: never
          has_ripe?: never
          has_ripestat?: never
          has_rpki?: never
          has_strong_external?: never
          is_attack?: never
          qrator_count?: number | null
          qrator_events_count_30m?: number | null
          ripe_events_count_30m?: number | null
          ripestat_count?: number | null
          ripestat_events_count_30m?: number | null
          rpki_count?: number | null
          rpki_events_count_30m?: number | null
          strong_count?: number | null
          ti_abuse_avg_score?: number | null
          ti_abuse_high_ratio?: number | null
          ti_combined_score?: number | null
          ti_ips_total?: number | null
          timestamp?: string | null
          wanguard_attack_count_30m?: number | null
          wanguard_max_bps_30m?: number | null
          wanguard_severity_class?: string | null
        }
        Relationships: []
      }
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      incident_dedup_key: {
        Args: { p_created_at: string; p_signals: string[] }
        Returns: string
      }
      is_master_admin: { Args: never; Returns: boolean }
    }
    Enums: {
      app_role: "admin" | "moderator" | "user"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "moderator", "user"],
    },
  },
} as const
